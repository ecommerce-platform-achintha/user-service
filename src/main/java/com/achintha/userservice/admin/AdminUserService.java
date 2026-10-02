package com.achintha.userservice.admin;

import com.achintha.userservice.admin.AdminRequests.CreateAdminRequest;
import com.achintha.userservice.audit.AuditService;
import com.achintha.userservice.common.PageResponse;
import com.achintha.userservice.exception.NotFoundException;
import com.achintha.userservice.outbox.UserEventPublisher;
import com.achintha.userservice.ports.NotificationPort;
import com.achintha.userservice.security.Actor;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.UniqueConstraints;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserAccountFactory;
import com.achintha.userservice.user.UserRepository;
import com.achintha.userservice.user.UserResponses.AdminUserResponse;
import com.achintha.userservice.user.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Admin reads and super-admin account management. */
@Service
@RequiredArgsConstructor
public class AdminUserService {

    private final UserRepository userRepository;
    private final UserAccountFactory accountFactory;
    private final UserEventPublisher events;
    private final AuditService audit;
    private final NotificationPort notifications;

    @Transactional(readOnly = true)
    public PageResponse<AdminUserResponse> search(Role role, UserStatus status, String text, Pageable pageable) {
        return PageResponse.from(userRepository.findAll(UserSearch.matching(role, status, text), pageable),
                AdminUserResponse::from);
    }

    @Transactional(readOnly = true)
    public PageResponse<AdminUserResponse> pendingMerchants(Pageable pageable) {
        return PageResponse.from(
                userRepository.findAllByRoleAndStatus(Role.ROLE_MERCHANT, UserStatus.PENDING_APPROVAL, pageable),
                AdminUserResponse::from);
    }

    @Transactional(readOnly = true)
    public AdminUserResponse get(String publicId) {
        return userRepository.findByPublicId(publicId)
                .map(AdminUserResponse::from)
                .orElseThrow(() -> new NotFoundException("User not found"));
    }

    @Transactional(readOnly = true)
    public PageResponse<AdminUserResponse> admins(Pageable pageable) {
        return PageResponse.from(userRepository.findAllByRole(Role.ROLE_ADMIN, pageable), AdminUserResponse::from);
    }

    /** Super admin creates an admin with a temporary password; the admin must change it at first sign-in. */
    @Transactional
    public AdminUserResponse createAdmin(Actor superAdmin, CreateAdminRequest request) {
        User admin = accountFactory.newUser(Role.ROLE_ADMIN, UserStatus.ACTIVE, request.email(),
                request.temporaryPassword(), request.firstName(), request.lastName(), request.nic(),
                request.phone(), superAdmin.publicId());
        admin.setMustChangePassword(true);
        try {
            userRepository.saveAndFlush(admin);
        } catch (DataIntegrityViolationException e) {
            throw UniqueConstraints.translate(e);
        }
        events.userRegistered(admin);
        audit.recordUserChange(superAdmin, "ADMIN_CREATED", admin, null, null);
        notifications.notify(admin.getEmail(), "ADMIN_CREATED", "Your admin account was created");
        return AdminUserResponse.from(admin);
    }
}
