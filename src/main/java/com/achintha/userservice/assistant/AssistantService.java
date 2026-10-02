package com.achintha.userservice.assistant;

import com.achintha.userservice.assistant.AssistantRequests.CreateAssistantRequest;
import com.achintha.userservice.audit.AuditService;
import com.achintha.userservice.auth.TokenRevocationService;
import com.achintha.userservice.common.Nic;
import com.achintha.userservice.common.PageResponse;
import com.achintha.userservice.common.TextSanitizer;
import com.achintha.userservice.exception.ApiException;
import com.achintha.userservice.exception.ErrorCode;
import com.achintha.userservice.exception.NotFoundException;
import com.achintha.userservice.outbox.UserEventPublisher;
import com.achintha.userservice.ports.NotificationPort;
import com.achintha.userservice.security.Actor;
import com.achintha.userservice.user.AssistantPermission;
import com.achintha.userservice.user.AssistantStatus;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.UniqueConstraints;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserAccountFactory;
import com.achintha.userservice.user.UserRepository;
import com.achintha.userservice.user.UserResponses.AssistantResponse;
import com.achintha.userservice.user.UserStatus;
import java.time.Clock;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Merchant-owner assistant management. Every query is scoped by the {@code storeId} of the caller's token (never by
 * request data); another store's assistant is reported as 404.
 */
@Service
@RequiredArgsConstructor
public class AssistantService {

    private static final List<AssistantStatus> NIC_HOLDING = List.of(AssistantStatus.ACTIVE,
            AssistantStatus.BANNED_BY_ADMIN);

    private final UserRepository userRepository;
    private final UserAccountFactory accountFactory;
    private final TokenRevocationService tokenRevocation;
    private final UserEventPublisher events;
    private final AuditService audit;
    private final NotificationPort notifications;
    private final Clock clock;

    /** Only an approved merchant may add assistants (D21); the silent ban grace still counts as active. */
    @Transactional
    public AssistantResponse create(Actor owner, CreateAssistantRequest request) {
        User merchant = owner(owner);
        if (merchant.getStatus() != UserStatus.ACTIVE && merchant.getStatus() != UserStatus.BAN_GRACE) {
            throw ApiException.conflict(ErrorCode.MERCHANT_NOT_ACTIVE,
                    "Assistants can be added once the merchant account is approved and active");
        }
        String nic = Nic.normalize(request.nic());
        if (userRepository.existsByRoleAndNicAndAssistantStatusIn(Role.ROLE_ASSISTANT, nic, NIC_HOLDING)) {
            throw ApiException.conflict(ErrorCode.NIC_ALREADY_ASSIGNED, UniqueConstraints.NIC_IN_USE_MESSAGE);
        }
        User assistant = accountFactory.newUser(Role.ROLE_ASSISTANT, UserStatus.ACTIVE, request.email(),
                request.temporaryPassword(), request.firstName(), request.lastName(), nic, request.phone(),
                owner.publicId());
        assistant.setAssistantStatus(AssistantStatus.ACTIVE);
        assistant.setStoreId(merchant.getStoreId());
        assistant.setPermissions(EnumSet.copyOf(request.permissions()));
        assistant.setMustChangePassword(true);
        save(assistant);
        events.userRegistered(assistant);
        events.assistantChanged(assistant, "CREATED");
        audit.recordUserChange(owner, "ASSISTANT_CREATED", assistant, null, null);
        notifications.notify(assistant.getEmail(), "ASSISTANT_CREATED", "Your assistant account was created");
        return AssistantResponse.from(assistant);
    }

    @Transactional(readOnly = true)
    public PageResponse<AssistantResponse> list(Actor owner, Pageable pageable) {
        return PageResponse.from(userRepository.findAllByRoleAndStoreId(Role.ROLE_ASSISTANT, storeId(owner),
                pageable), AssistantResponse::from);
    }

    @Transactional(readOnly = true)
    public AssistantResponse get(Actor owner, String publicId) {
        return AssistantResponse.from(find(owner, publicId));
    }

    @Transactional
    public AssistantResponse updatePermissions(Actor owner, String publicId, Set<AssistantPermission> permissions) {
        User assistant = find(owner, publicId);
        requireStatus(assistant, AssistantStatus.ACTIVE, AssistantStatus.BANNED_BY_MERCHANT);
        Map<String, Object> before = AuditService.snapshot(assistant);
        assistant.getPermissions().clear();
        assistant.getPermissions().addAll(permissions);
        tokenRevocation.revokeAccessTokens(assistant, "PERMISSIONS_CHANGED");
        events.assistantChanged(assistant, "PERMISSIONS_CHANGED");
        audit.recordUserChange(owner, "ASSISTANT_PERMISSIONS_CHANGED", assistant, before, null);
        return AssistantResponse.from(assistant);
    }

    /** Merchant ban: the NIC is released (section 13, point 5). */
    @Transactional
    public AssistantResponse ban(Actor owner, String publicId, String reason) {
        User assistant = find(owner, publicId);
        requireStatus(assistant, AssistantStatus.ACTIVE);
        return change(owner, assistant, AssistantStatus.BANNED_BY_MERCHANT, reason, "BANNED_BY_MERCHANT",
                "ASSISTANT_BANNED", true);
    }

    /** Lifts a merchant ban; fails with 409 if the NIC was meanwhile taken by another store's assistant. */
    @Transactional
    public AssistantResponse unban(Actor owner, String publicId, String reason) {
        User assistant = find(owner, publicId);
        requireStatus(assistant, AssistantStatus.BANNED_BY_MERCHANT);
        if (userRepository.existsByRoleAndNicAndAssistantStatusIn(Role.ROLE_ASSISTANT, assistant.getNic(),
                NIC_HOLDING)) {
            throw ApiException.conflict(ErrorCode.NIC_ALREADY_ASSIGNED, UniqueConstraints.NIC_IN_USE_MESSAGE);
        }
        return change(owner, assistant, AssistantStatus.ACTIVE, reason, "UNBANNED", "ASSISTANT_UNBANNED", false);
    }

    /** Removal is final for this account; the NIC is released. */
    @Transactional
    public AssistantResponse remove(Actor owner, String publicId, String reason) {
        User assistant = find(owner, publicId);
        requireStatus(assistant, AssistantStatus.ACTIVE, AssistantStatus.BANNED_BY_MERCHANT);
        return change(owner, assistant, AssistantStatus.REMOVED, reason, "REMOVED", "ASSISTANT_REMOVED", true);
    }

    private AssistantResponse change(Actor owner, User assistant, AssistantStatus newStatus, String reason,
                                     String change, String action, boolean revokeRefresh) {
        Map<String, Object> before = AuditService.snapshot(assistant);
        assistant.changeAssistantStatus(newStatus, TextSanitizer.clean(reason), owner.publicId(), clock.instant());
        save(assistant);
        if (revokeRefresh) {
            tokenRevocation.revokeAllTokens(assistant, change);
        } else {
            tokenRevocation.revokeAccessTokens(assistant, change);
        }
        events.assistantChanged(assistant, change);
        audit.recordUserChange(owner, action, assistant, before, assistant.getStatusReason());
        return AssistantResponse.from(assistant);
    }

    private static void requireStatus(User assistant, AssistantStatus... allowed) {
        for (AssistantStatus status : allowed) {
            if (assistant.getAssistantStatus() == status) {
                return;
            }
        }
        throw ApiException.invalidTransition("Not allowed while the assistant is " + assistant.getAssistantStatus());
    }

    private User find(Actor owner, String publicId) {
        return userRepository.findByPublicIdAndRoleAndStoreId(publicId, Role.ROLE_ASSISTANT, storeId(owner))
                .orElseThrow(() -> new NotFoundException("Assistant not found"));
    }

    private User owner(Actor owner) {
        return userRepository.findById(owner.id())
                .filter(user -> user.isMerchant() && user.getStoreId().equals(storeId(owner)))
                .orElseThrow(() -> new NotFoundException("Merchant not found"));
    }

    private static UUID storeId(Actor owner) {
        if (owner.storeId() == null) {
            throw new NotFoundException("Store not found");
        }
        return owner.storeId();
    }

    private void save(User user) {
        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            throw UniqueConstraints.translate(e);
        }
    }
}
