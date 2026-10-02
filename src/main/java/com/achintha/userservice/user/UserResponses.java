package com.achintha.userservice.user;

import com.achintha.userservice.common.Nic;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.List;

/**
 * Response DTOs. None of them has a password field, and internal UUIDs are never exposed (public ids only).
 */
public final class UserResponses {

    private UserResponses() {
    }

    private static List<String> permissionNames(User user) {
        return user.isAssistant()
                ? user.effectivePermissions().stream().map(AssistantPermission::name).sorted().toList()
                : null;
    }

    /**
     * The caller's own profile ({@code /api/users/me}, registration). Full NIC (the owner may see it); status and
     * reason as visible to the user.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ProfileResponse(
            String publicId,
            String email,
            String firstName,
            String lastName,
            String nic,
            String phone,
            Role role,
            UserStatus status,
            String statusReason,
            boolean mustChangePassword,
            AssistantStatus assistantStatus,
            List<String> permissions,
            Instant createdAt) {

        public static ProfileResponse from(User user) {
            return new ProfileResponse(user.getPublicId(), user.getEmail(), user.getFirstName(), user.getLastName(),
                    user.getNic(), user.getPhone(), user.getRole(), user.visibleStatus(), user.visibleStatusReason(),
                    user.isMustChangePassword(), user.getAssistantStatus(), permissionNames(user),
                    user.getCreatedAt());
        }
    }

    /** Admin view: real status (including {@code BAN_GRACE}), ban timeline, full NIC. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AdminUserResponse(
            String publicId,
            String email,
            String firstName,
            String lastName,
            String nic,
            String phone,
            Role role,
            UserStatus status,
            String statusReason,
            String statusChangedBy,
            Instant statusChangedAt,
            Instant banEffectiveAt,
            Instant banAnnouncedAt,
            AssistantStatus assistantStatus,
            List<String> permissions,
            Integer applicationAttempts,
            boolean mustChangePassword,
            Instant lockedUntil,
            Instant createdAt) {

        public static AdminUserResponse from(User user) {
            return new AdminUserResponse(user.getPublicId(), user.getEmail(), user.getFirstName(),
                    user.getLastName(), user.getNic(), user.getPhone(), user.getRole(), user.getStatus(),
                    user.getStatusReason(), user.getStatusChangedBy(), user.getStatusChangedAt(),
                    user.getBanEffectiveAt(), user.getBanAnnouncedAt(), user.getAssistantStatus(),
                    permissionNames(user), user.isMerchant() ? user.getApplicationAttempts() : null,
                    user.isMustChangePassword(), user.getLockedUntil(), user.getCreatedAt());
        }
    }

    /** Merchant owner's view of an assistant: NIC masked. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AssistantResponse(
            String publicId,
            String email,
            String firstName,
            String lastName,
            String nic,
            String phone,
            AssistantStatus assistantStatus,
            String statusReason,
            List<String> permissions,
            boolean mustChangePassword,
            Instant createdAt) {

        public static AssistantResponse from(User user) {
            return new AssistantResponse(user.getPublicId(), user.getEmail(), user.getFirstName(),
                    user.getLastName(), Nic.mask(user.getNic()), user.getPhone(), user.getAssistantStatus(),
                    user.getStatusReason(), permissionNames(user), user.isMustChangePassword(),
                    user.getCreatedAt());
        }
    }
}
