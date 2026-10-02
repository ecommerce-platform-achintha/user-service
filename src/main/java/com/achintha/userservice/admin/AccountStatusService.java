package com.achintha.userservice.admin;

import com.achintha.userservice.audit.AuditService;
import com.achintha.userservice.auth.TokenRevocationService;
import com.achintha.userservice.common.TextSanitizer;
import com.achintha.userservice.exception.ApiException;
import com.achintha.userservice.exception.NotFoundException;
import com.achintha.userservice.outbox.UserEventPublisher;
import com.achintha.userservice.ports.NotificationPort;
import com.achintha.userservice.security.Actor;
import com.achintha.userservice.user.AssistantStatus;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.UniqueConstraints;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserRepository;
import com.achintha.userservice.user.UserStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Bans and unbans (section 3.2). Every change records reason, actor and time, increments the token version, writes
 * an audit row and emits events through the outbox.
 * <ul>
 *   <li>merchant: {@code ACTIVE -> BAN_GRACE} (silent, {@code banEffectiveAt = now + timers.ban-grace-days}); the
 *       scheduler later makes it {@code BANNED} ({@link #enforceMerchantBan});</li>
 *   <li>customer: {@code ACTIVE -> BANNED} immediately, reason visible, sign-in still allowed;</li>
 *   <li>admin (super admin only): {@code ACTIVE -> BANNED}, all tokens revoked, sign-in refused;</li>
 *   <li>assistant (admin): {@code BANNED_BY_ADMIN}, the NIC stays blocked permanently.</li>
 * </ul>
 * The super admin can never be changed through the API.
 */
@Slf4j
@Service
public class AccountStatusService {

    private final UserRepository userRepository;
    private final TokenRevocationService tokenRevocation;
    private final UserEventPublisher events;
    private final AuditService audit;
    private final NotificationPort notifications;
    private final Clock clock;
    private final int banGraceDays;

    public AccountStatusService(UserRepository userRepository, TokenRevocationService tokenRevocation,
                                UserEventPublisher events, AuditService audit, NotificationPort notifications,
                                Clock clock, @Value("${timers.ban-grace-days:14}") int banGraceDays) {
        this.userRepository = userRepository;
        this.tokenRevocation = tokenRevocation;
        this.events = events;
        this.audit = audit;
        this.notifications = notifications;
        this.clock = clock;
        this.banGraceDays = banGraceDays;
    }

    // ---------------------------------------------------------------------------------------------------- merchants

    @Transactional
    public User banMerchant(Actor admin, String publicId, String reason) {
        User merchant = find(publicId, Role.ROLE_MERCHANT, "Merchant not found");
        if (merchant.getStatus() != UserStatus.ACTIVE) {
            throw ApiException.invalidTransition("Only an active merchant can be banned (status "
                    + merchant.getStatus() + ")");
        }
        Map<String, Object> before = AuditService.snapshot(merchant);
        Instant now = clock.instant();
        merchant.changeStatus(UserStatus.BAN_GRACE, TextSanitizer.clean(reason), admin.publicId(), now);
        merchant.setBanEffectiveAt(now.plus(Duration.ofDays(banGraceDays)));
        merchant.setBanAnnouncedAt(null);
        events.statusChanged(merchant, UserStatus.ACTIVE);
        // Silent: access tokens are re-issued on the next refresh, the merchant is not signed out or told
        tokenRevocation.revokeAccessTokens(merchant, "BANNED");
        audit.recordUserChange(admin, "MERCHANT_BANNED", merchant, before, merchant.getStatusReason());
        return merchant;
    }

    /**
     * End of the grace period: the ban becomes {@code BANNED} and visible, every assistant of the store is signed
     * out and can no longer sign in. Idempotent: does nothing unless the merchant is still in a due grace period.
     *
     * @return {@code true} if the ban was enforced now
     */
    @Transactional
    public boolean enforceMerchantBan(UUID merchantId) {
        Instant now = clock.instant();
        User merchant = userRepository.findById(merchantId).orElse(null);
        if (merchant == null || merchant.getStatus() != UserStatus.BAN_GRACE
                || merchant.getBanEffectiveAt() == null || merchant.getBanEffectiveAt().isAfter(now)) {
            return false;
        }
        Map<String, Object> before = AuditService.snapshot(merchant);
        merchant.changeStatus(UserStatus.BANNED, merchant.getStatusReason(), Actor.SYSTEM, now);
        merchant.setBanAnnouncedAt(now);
        events.statusChanged(merchant, UserStatus.BAN_GRACE);
        tokenRevocation.revokeAllTokens(merchant, "BAN_ANNOUNCED");
        for (User assistant : userRepository.findAllByRoleAndStoreId(Role.ROLE_ASSISTANT, merchant.getStoreId())) {
            if (assistant.getAssistantStatus() != AssistantStatus.REMOVED) {
                tokenRevocation.revokeAllTokens(assistant, "MERCHANT_BANNED");
            }
        }
        audit.recordUserChange(Actor.system(), "MERCHANT_BAN_ENFORCED", merchant, before,
                merchant.getStatusReason());
        notifications.notify(merchant.getEmail(), "MERCHANT_BANNED", "Your merchant account has been banned");
        log.info("Merchant {} ban enforced after the grace period", merchant.getPublicId());
        return true;
    }

    @Transactional
    public User unbanMerchant(Actor admin, String publicId, String reason) {
        User merchant = find(publicId, Role.ROLE_MERCHANT, "Merchant not found");
        if (merchant.getStatus() != UserStatus.BAN_GRACE && merchant.getStatus() != UserStatus.BANNED) {
            throw ApiException.invalidTransition("The merchant is not banned");
        }
        return unban(admin, merchant, reason, "MERCHANT_UNBANNED");
    }

    // ---------------------------------------------------------------------------------------------------- customers

    @Transactional
    public User banCustomer(Actor admin, String publicId, String reason) {
        User customer = find(publicId, Role.ROLE_CUSTOMER, "Customer not found");
        return banImmediately(admin, customer, reason, "CUSTOMER_BANNED", false);
    }

    @Transactional
    public User unbanCustomer(Actor admin, String publicId, String reason) {
        User customer = find(publicId, Role.ROLE_CUSTOMER, "Customer not found");
        if (customer.getStatus() != UserStatus.BANNED) {
            throw ApiException.invalidTransition("The customer is not banned");
        }
        return unban(admin, customer, reason, "CUSTOMER_UNBANNED");
    }

    // ------------------------------------------------------------------------------------------------------- admins

    @Transactional
    public User banAdmin(Actor superAdmin, String publicId, String reason) {
        User admin = find(publicId, Role.ROLE_ADMIN, "Admin not found");
        return banImmediately(superAdmin, admin, reason, "ADMIN_BANNED", true);
    }

    @Transactional
    public User unbanAdmin(Actor superAdmin, String publicId, String reason) {
        User admin = find(publicId, Role.ROLE_ADMIN, "Admin not found");
        if (admin.getStatus() != UserStatus.BANNED) {
            throw ApiException.invalidTransition("The admin is not banned");
        }
        return unban(superAdmin, admin, reason, "ADMIN_UNBANNED");
    }

    // --------------------------------------------------------------------------------------------------- assistants

    /** Admin ban for misconduct: permanent NIC block (section 13, point 5). */
    @Transactional
    public User banAssistant(Actor admin, String publicId, String reason) {
        User assistant = find(publicId, Role.ROLE_ASSISTANT, "Assistant not found");
        AssistantStatus current = assistant.getAssistantStatus();
        if (current != AssistantStatus.ACTIVE && current != AssistantStatus.BANNED_BY_MERCHANT) {
            throw ApiException.invalidTransition("The assistant cannot be banned (status " + current + ")");
        }
        Map<String, Object> before = AuditService.snapshot(assistant);
        assistant.changeAssistantStatus(AssistantStatus.BANNED_BY_ADMIN, TextSanitizer.clean(reason),
                admin.publicId(), clock.instant());
        try {
            userRepository.saveAndFlush(assistant);
        } catch (DataIntegrityViolationException e) {
            throw UniqueConstraints.translate(e);
        }
        tokenRevocation.revokeAllTokens(assistant, "BANNED_BY_ADMIN");
        events.assistantChanged(assistant, "BANNED_BY_ADMIN");
        audit.recordUserChange(admin, "ASSISTANT_BANNED_BY_ADMIN", assistant, before, assistant.getStatusReason());
        return assistant;
    }

    // ------------------------------------------------------------------------------------------------------ helpers

    private User banImmediately(Actor actor, User user, String reason, String action, boolean revokeRefresh) {
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw ApiException.invalidTransition("Only an active account can be banned");
        }
        Map<String, Object> before = AuditService.snapshot(user);
        Instant now = clock.instant();
        user.changeStatus(UserStatus.BANNED, TextSanitizer.clean(reason), actor.publicId(), now);
        user.setBanAnnouncedAt(now);
        events.statusChanged(user, UserStatus.ACTIVE);
        if (revokeRefresh) {
            tokenRevocation.revokeAllTokens(user, "BANNED");
        } else {
            tokenRevocation.revokeAccessTokens(user, "BANNED");
        }
        audit.recordUserChange(actor, action, user, before, user.getStatusReason());
        notifications.notify(user.getEmail(), action, "Your account has been banned");
        return user;
    }

    private User unban(Actor actor, User user, String reason, String action) {
        Map<String, Object> before = AuditService.snapshot(user);
        UserStatus previous = user.getStatus();
        user.changeStatus(UserStatus.ACTIVE, TextSanitizer.clean(reason), actor.publicId(), clock.instant());
        user.setBanEffectiveAt(null);
        user.setBanAnnouncedAt(null);
        events.statusChanged(user, previous);
        tokenRevocation.revokeAccessTokens(user, "UNBANNED");
        audit.recordUserChange(actor, action, user, before, user.getStatusReason());
        notifications.notify(user.getEmail(), action, "Your account has been reinstated");
        return user;
    }

    private User find(String publicId, Role role, String notFoundMessage) {
        return userRepository.findByPublicIdAndRole(publicId, role)
                .orElseThrow(() -> new NotFoundException(notFoundMessage));
    }
}
