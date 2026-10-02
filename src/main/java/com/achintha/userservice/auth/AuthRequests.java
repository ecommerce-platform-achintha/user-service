package com.achintha.userservice.auth;

import com.achintha.userservice.common.PasswordPolicy.ValidPassword;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Small request bodies of the auth endpoints. Secrets are masked in {@code toString()}. */
public final class AuthRequests {

    private AuthRequests() {
    }

    public record RefreshRequest(@NotBlank @Size(max = 100) String refreshToken) {

        @Override
        public String toString() {
            return "RefreshRequest[refreshToken=****]";
        }
    }

    public record LogoutRequest(@NotBlank @Size(max = 100) String refreshToken) {

        @Override
        public String toString() {
            return "LogoutRequest[refreshToken=****]";
        }
    }

    public record ChangePasswordRequest(
            @NotBlank @Size(max = 128) String currentPassword,
            @NotBlank @ValidPassword String newPassword) {

        @Override
        public String toString() {
            return "ChangePasswordRequest[currentPassword=****, newPassword=****]";
        }
    }

    public record ServiceTokenRequest(
            @NotBlank @Size(max = 64) String clientId,
            @NotBlank @Size(max = 256) String clientSecret) {

        @Override
        public String toString() {
            return "ServiceTokenRequest[clientId=" + clientId + ", clientSecret=****]";
        }
    }

    public record ServiceTokenResponse(String accessToken, String tokenType, long expiresIn,
                                       java.time.Instant expiresAt) {

        @Override
        public String toString() {
            return "ServiceTokenResponse[accessToken=****, expiresAt=" + expiresAt + "]";
        }
    }
}
