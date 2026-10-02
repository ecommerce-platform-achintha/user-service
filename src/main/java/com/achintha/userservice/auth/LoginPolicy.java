package com.achintha.userservice.auth;

import com.achintha.userservice.exception.ApiException;
import com.achintha.userservice.exception.ErrorCode;
import com.achintha.userservice.user.AssistantStatus;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserRepository;
import com.achintha.userservice.user.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Who may sign in (and refresh), after the password has been verified (sections 3.1 and 3.2):
 * <ul>
 *   <li>refused: banned admins (with the reason), banned or removed assistants (with the reason), and assistants
 *       whose merchant is {@code BANNED} (announced; {@code BAN_GRACE} is silent and still allowed);</li>
 *   <li>allowed: customers in any status (a banned customer can view history), merchants in any status (pending,
 *       rejected, grace, banned owner for history), the super admin, active admins and assistants.</li>
 * </ul>
 */
@Component
@RequiredArgsConstructor
public class LoginPolicy {

    private final UserRepository userRepository;

    public void check(User user) {
        switch (user.getRole()) {
            case ROLE_ADMIN -> {
                if (user.getStatus() == UserStatus.BANNED) {
                    throw ApiException.forbidden(ErrorCode.ACCOUNT_BANNED,
                            withReason("Your account has been banned", user.visibleStatusReason()));
                }
            }
            case ROLE_ASSISTANT -> checkAssistant(user);
            default -> {
                // customers, merchants and the super admin can always sign in
            }
        }
    }

    private void checkAssistant(User user) {
        AssistantStatus status = user.getAssistantStatus();
        if (status == AssistantStatus.REMOVED) {
            throw ApiException.forbidden(ErrorCode.ACCOUNT_REMOVED,
                    withReason("Your assistant account has been removed", user.visibleStatusReason()));
        }
        if (status != AssistantStatus.ACTIVE) {
            throw ApiException.forbidden(ErrorCode.ACCOUNT_BANNED,
                    withReason("Your assistant account has been banned", user.visibleStatusReason()));
        }
        boolean merchantBanned = userRepository.findByRoleAndStoreId(Role.ROLE_MERCHANT, user.getStoreId())
                .map(merchant -> merchant.getStatus() == UserStatus.BANNED)
                .orElse(true);
        if (merchantBanned) {
            throw ApiException.forbidden(ErrorCode.MERCHANT_BANNED,
                    "The merchant account of this store is banned; assistant sign-in is disabled");
        }
    }

    private static String withReason(String message, String reason) {
        return reason == null ? message : message + ". Reason: " + reason;
    }
}
