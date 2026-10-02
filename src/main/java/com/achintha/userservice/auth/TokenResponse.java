package com.achintha.userservice.auth;

import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.UserStatus;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;

/**
 * Login / refresh / change-password response.
 *
 * @param status       as visible to the user ({@code BAN_GRACE} is shown as {@code ACTIVE})
 * @param statusReason only when it should be visible (rejected, banned customer, announced merchant ban)
 */
public record TokenResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        Instant expiresAt,
        String refreshToken,
        Instant refreshTokenExpiresAt,
        String publicId,
        Role role,
        UserStatus status,
        @JsonInclude(JsonInclude.Include.NON_NULL) String statusReason,
        boolean mustChangePassword) {

    @Override
    public String toString() {
        return "TokenResponse[publicId=" + publicId + ", role=" + role + ", status=" + status + ", tokens=****]";
    }
}
