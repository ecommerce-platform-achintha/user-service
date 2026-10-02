package com.achintha.userservice.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.achintha.userservice.support.IntegrationTest;
import com.achintha.userservice.user.AssistantPermission;
import com.achintha.userservice.user.AssistantStatus;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserStatus;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/** Sign-in rules per role and status (sections 3.1-3.3), lockout, refresh rotation and token revocation. */
class LoginRulesTest extends IntegrationTest {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    // ---------------------------------------------------------------------------------------- status x role rules

    @Test
    void activeAccountsOfEveryRoleCanSignIn() throws Exception {
        User merchant = merchant(UserStatus.ACTIVE);
        for (User user : new User[] {customer(), merchant, assistant(merchant, Set.of()), admin()}) {
            login(user.getEmail(), PASSWORD)
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tokenType").value("Bearer"))
                    .andExpect(jsonPath("$.expiresIn").value(600))
                    .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                    .andExpect(jsonPath("$.role").value(user.getRole().name()))
                    .andExpect(jsonPath("$.status").value("ACTIVE"))
                    .andExpect(jsonPath("$.statusReason").doesNotExist())
                    .andExpect(jsonPath("$.mustChangePassword").value(false));
        }
    }

    @Test
    void bannedCustomerCanSignInAndSeesTheReason() throws Exception {
        User customer = createUser(Role.ROLE_CUSTOMER, UserStatus.BANNED, u -> {
            u.setStatusReason("Repeated fake orders");
            u.setBanAnnouncedAt(Instant.now());
        });
        login(customer.getEmail(), PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("BANNED"))
                .andExpect(jsonPath("$.statusReason").value("Repeated fake orders"));
    }

    @Test
    void merchantsCanSignInInEveryStatusAndSeeOnlyVisibleReasons() throws Exception {
        User pending = merchant(UserStatus.PENDING_APPROVAL);
        User rejected = createUser(Role.ROLE_MERCHANT, UserStatus.REJECTED, u -> u.setStatusReason("Blurry documents"));
        User grace = createUser(Role.ROLE_MERCHANT, UserStatus.BAN_GRACE, u -> {
            u.setStatusReason("Secret ban reason");
            u.setBanEffectiveAt(Instant.now().plus(Duration.ofDays(10)));
        });
        User banned = createUser(Role.ROLE_MERCHANT, UserStatus.BANNED, u -> {
            u.setStatusReason("Fraud");
            u.setBanAnnouncedAt(Instant.now());
        });

        login(pending.getEmail(), PASSWORD).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PENDING_APPROVAL"))
                .andExpect(jsonPath("$.statusReason").doesNotExist());
        login(rejected.getEmail(), PASSWORD).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REJECTED"))
                .andExpect(jsonPath("$.statusReason").value("Blurry documents"));
        // The grace period is silent: shown as ACTIVE, no reason
        String graceBody = loginOk(grace.getEmail(), PASSWORD);
        assertThat(read(graceBody, "$.status")).isEqualTo("ACTIVE");
        assertThat(graceBody).doesNotContain("Secret ban reason").doesNotContain("BAN_GRACE");
        mockMvc.perform(withBearer(get("/api/users/me"), read(graceBody, "$.accessToken")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.statusReason").doesNotExist());
        login(banned.getEmail(), PASSWORD).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("BANNED"))
                .andExpect(jsonPath("$.statusReason").value("Fraud"));
    }

    @Test
    void bannedAdminIsRefusedWithTheReason() throws Exception {
        User admin = createUser(Role.ROLE_ADMIN, UserStatus.BANNED, u -> u.setStatusReason("Data leak"));
        login(admin.getEmail(), PASSWORD)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCOUNT_BANNED"))
                .andExpect(jsonPath("$.message").value("Your account has been banned. Reason: Data leak"));
        // ...but only after the password is verified
        login(admin.getEmail(), "Wrong-Password-123")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
    }

    @Test
    void bannedRemovedAndOrphanedAssistantsAreRefused() throws Exception {
        User merchant = merchant(UserStatus.ACTIVE);
        User byMerchant = assistantWith(merchant, AssistantStatus.BANNED_BY_MERCHANT, "Late every day");
        User byAdmin = assistantWith(merchant, AssistantStatus.BANNED_BY_ADMIN, "Misconduct");
        User removed = assistantWith(merchant, AssistantStatus.REMOVED, "Left the company");

        login(byMerchant.getEmail(), PASSWORD).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCOUNT_BANNED"))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("Late every day")));
        login(byAdmin.getEmail(), PASSWORD).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCOUNT_BANNED"));
        login(removed.getEmail(), PASSWORD).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCOUNT_REMOVED"));
    }

    @Test
    void assistantsFollowTheirMerchantsAnnouncedBanOnly() throws Exception {
        User graceMerchant = createUser(Role.ROLE_MERCHANT, UserStatus.BAN_GRACE,
                u -> u.setBanEffectiveAt(Instant.now().plus(Duration.ofDays(3))));
        User bannedMerchant = createUser(Role.ROLE_MERCHANT, UserStatus.BANNED,
                u -> u.setBanAnnouncedAt(Instant.now()));

        login(assistant(graceMerchant, Set.of()).getEmail(), PASSWORD).andExpect(status().isOk());
        login(assistant(bannedMerchant, Set.of()).getEmail(), PASSWORD)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("MERCHANT_BANNED"));
    }

    // ------------------------------------------------------------------------------------- credentials, lockout

    @Test
    void wrongEmailAndWrongPasswordLookTheSame() throws Exception {
        User customer = customer();
        String wrongPassword = login(customer.getEmail(), "Wrong-Password-123")
                .andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString();
        String unknownEmail = login(uniqueEmail("nobody"), "Wrong-Password-123")
                .andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString();

        assertThat(read(wrongPassword, "$.message")).isEqualTo(read(unknownEmail, "$.message"))
                .isEqualTo("Invalid email or password");
        assertThat(read(wrongPassword, "$.code")).isEqualTo(read(unknownEmail, "$.code"))
                .isEqualTo("INVALID_CREDENTIALS");
    }

    @Test
    void accountIsLockedAfterFiveFailuresForFifteenMinutes() throws Exception {
        User customer = customer();
        for (int i = 0; i < 5; i++) {
            login(customer.getEmail(), "Wrong-Password-123").andExpect(status().isUnauthorized());
        }
        // Even the right password is refused while locked
        login(customer.getEmail(), PASSWORD)
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("TOO_MANY_LOGIN_ATTEMPTS"));

        clock.advance(Duration.ofMinutes(16));
        login(customer.getEmail(), PASSWORD).andExpect(status().isOk());
        assertThat(reload(customer).getFailedLoginCount()).isZero();
        assertThat(reload(customer).getLockedUntil()).isNull();
    }

    @Test
    void unknownEmailsAreLockedTooSoLockoutDoesNotRevealAccounts() throws Exception {
        String email = uniqueEmail("ghost");
        for (int i = 0; i < 5; i++) {
            login(email, "Wrong-Password-123").andExpect(status().isUnauthorized());
        }
        login(email, "Wrong-Password-123").andExpect(status().isTooManyRequests());
    }

    @Test
    void clientIpIsLockedAfterTooManyFailures(@Autowired LoginThrottleService throttle) throws Exception {
        String ip = "203.0.113." + (int) (Math.random() * 200);
        for (int i = 0; i < 3; i++) {
            throttle.recordFailure(LoginThrottleService.ipKey(ip), 3);
        }
        User customer = customer();
        mockMvc.perform(json(post("/api/auth/login").with(request -> {
                    request.setRemoteAddr(ip);
                    return request;
                }), "{\"email\":\"%s\",\"password\":\"%s\"}".formatted(customer.getEmail(), PASSWORD)))
                .andExpect(status().isTooManyRequests());
        login(customer.getEmail(), PASSWORD).andExpect(status().isOk()); // other IPs unaffected
    }

    // -------------------------------------------------------------------------------------- refresh rotation

    @Test
    void refreshRotatesAndReuseRevokesTheWholeFamily() throws Exception {
        User customer = customer();
        String first = read(loginOk(customer.getEmail(), PASSWORD), "$.refreshToken");

        String rotated = refresh(first).andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        String second = read(rotated, "$.refreshToken");
        assertThat(second).isNotEqualTo(first);

        // Replaying the first token: reuse detected, family revoked
        refresh(first).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_TOKEN_REUSED"));
        refresh(second).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));
        assertThat(refreshTokenRepository.countByUserIdAndRevokedAtIsNull(customer.getId())).isZero();

        // Only the hash is stored
        assertThat(refreshTokenRepository.findByTokenHash(second)).isEmpty();
        assertThat(refreshTokenRepository.findByTokenHash(RefreshTokenService.hash(second))).isPresent();
    }

    @Test
    void refreshTokensExpireAndLogoutRevokes() throws Exception {
        User customer = customer();
        String body = loginOk(customer.getEmail(), PASSWORD);

        mockMvc.perform(json(withBearer(post("/api/auth/logout"), read(body, "$.accessToken")),
                        "{\"refreshToken\":\"%s\"}".formatted(read(body, "$.refreshToken"))))
                .andExpect(status().isNoContent());
        refresh(read(body, "$.refreshToken")).andExpect(status().isUnauthorized());

        String other = read(loginOk(customer.getEmail(), PASSWORD), "$.refreshToken");
        clock.advance(Duration.ofDays(15));
        refresh(other).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));
    }

    @Test
    void refreshAppliesTheSignInRulesAgain() throws Exception {
        User merchant = merchant(UserStatus.ACTIVE);
        User assistant = assistant(merchant, Set.of(AssistantPermission.ORDER_VIEW));
        String refreshToken = read(loginOk(assistant.getEmail(), PASSWORD), "$.refreshToken");

        transactionTemplate.executeWithoutResult(tx -> userRepository.findById(assistant.getId()).orElseThrow()
                .setAssistantStatus(AssistantStatus.REMOVED));

        refresh(refreshToken).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCOUNT_REMOVED"));
        assertThat(refreshTokenRepository.countByUserIdAndRevokedAtIsNull(assistant.getId())).isZero();
    }

    // ---------------------------------------------------------------------------- token version, password change

    @Test
    void bumpingTheTokenVersionRevokesOutstandingAccessTokens() throws Exception {
        User customer = customer();
        String token = read(loginOk(customer.getEmail(), PASSWORD), "$.accessToken");
        mockMvc.perform(withBearer(get("/api/users/me"), token)).andExpect(status().isOk());

        transactionTemplate.executeWithoutResult(tx ->
                userRepository.findById(customer.getId()).orElseThrow().incrementTokenVersion());

        mockMvc.perform(withBearer(get("/api/users/me"), token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_REVOKED"));
    }

    @Test
    void mustChangePasswordBlocksEverythingUntilChanged() throws Exception {
        User admin = createUser(Role.ROLE_ADMIN, UserStatus.ACTIVE, u -> u.setMustChangePassword(true));
        String body = loginOk(admin.getEmail(), PASSWORD);
        assertThat(read(body, "$.mustChangePassword")).isEqualTo("true");
        String token = read(body, "$.accessToken");

        mockMvc.perform(withBearer(get("/api/users/me"), token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PASSWORD_CHANGE_REQUIRED"));
        mockMvc.perform(withBearer(get("/api/admin/users"), token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PASSWORD_CHANGE_REQUIRED"));

        // Weak, wrong-current and same-password attempts are refused
        changePassword(token, PASSWORD, "short").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
        changePassword(token, "Not-My-Password-1", "Brand-New-Passphrase-7").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        changePassword(token, PASSWORD, PASSWORD).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("PASSWORD_REUSED"));

        String changed = changePassword(token, PASSWORD, "Brand-New-Passphrase-7")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mustChangePassword").value(false))
                .andReturn().getResponse().getContentAsString();

        // The old token is revoked; the new one works
        mockMvc.perform(withBearer(get("/api/users/me"), token)).andExpect(status().isUnauthorized());
        mockMvc.perform(withBearer(get("/api/users/me"), read(changed, "$.accessToken"))).andExpect(status().isOk());
        refresh(read(body, "$.refreshToken")).andExpect(status().isUnauthorized());
        login(admin.getEmail(), "Brand-New-Passphrase-7").andExpect(status().isOk());
    }

    // ------------------------------------------------------------------------------------------- service tokens

    @Test
    void serviceTokenRequiresValidClientCredentials() throws Exception {
        String body = mockMvc.perform(json(post("/internal/auth/service-token"),
                        "{\"clientId\":\"order-service\",\"clientSecret\":\"%s\"}".formatted(SERVICE_CLIENT_SECRET)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expiresIn").value(300))
                .andReturn().getResponse().getContentAsString();

        User customer = customer();
        mockMvc.perform(withBearer(get("/internal/users/" + customer.getId() + "/security-state"),
                        read(body, "$.accessToken")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tv").value(0))
                .andExpect(jsonPath("$.role").value("ROLE_CUSTOMER"));

        mockMvc.perform(json(post("/internal/auth/service-token"),
                        "{\"clientId\":\"order-service\",\"clientSecret\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CLIENT_CREDENTIALS"));
        mockMvc.perform(json(post("/internal/auth/service-token"),
                        "{\"clientId\":\"unknown-service\",\"clientSecret\":\"%s\"}".formatted(SERVICE_CLIENT_SECRET)))
                .andExpect(status().isUnauthorized());
    }

    // ------------------------------------------------------------------------------------------------- helpers

    private User assistantWith(User merchant, AssistantStatus status, String reason) {
        return createUser(Role.ROLE_ASSISTANT, UserStatus.ACTIVE, u -> {
            u.setStoreId(merchant.getStoreId());
            u.setAssistantStatus(status);
            u.setStatusReason(reason);
        });
    }

    private org.springframework.test.web.servlet.ResultActions refresh(String refreshToken) throws Exception {
        return mockMvc.perform(json(post("/api/auth/refresh"),
                "{\"refreshToken\":\"%s\"}".formatted(refreshToken)));
    }

    private org.springframework.test.web.servlet.ResultActions changePassword(String token, String current,
                                                                               String next) throws Exception {
        return mockMvc.perform(json(withBearer(post("/api/auth/change-password"), token),
                "{\"currentPassword\":\"%s\",\"newPassword\":\"%s\"}".formatted(current, next)));
    }
}
