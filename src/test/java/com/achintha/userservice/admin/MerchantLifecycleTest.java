package com.achintha.userservice.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.achintha.userservice.audit.AuditLogEntry;
import com.achintha.userservice.audit.AuditLogRepository;
import com.achintha.userservice.audit.AuditService;
import com.achintha.userservice.outbox.OutboxMessage;
import com.achintha.userservice.outbox.OutboxRepository;
import com.achintha.userservice.support.IntegrationTest;
import com.achintha.userservice.user.AssistantPermission;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserStatus;
import com.jayway.jsonpath.JsonPath;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/** Merchant approval, rejection, re-application limits and the silent 14-day ban timeline (D4). */
class MerchantLifecycleTest extends IntegrationTest {

    @Autowired
    private BanEnforcementJob banEnforcementJob;
    @Autowired
    private OutboxRepository outboxRepository;
    @Autowired
    private AuditLogRepository auditLogRepository;

    @Test
    void rejectResubmitUpToTheLimitThenApprove() throws Exception {
        String adminToken = tokenFor(admin());
        User merchant = registerMerchant();
        String merchantToken = tokenFor(merchant);

        // Listed as pending
        mockMvc.perform(withBearer(get("/api/admin/merchants/pending?size=100&sort=createdAt,desc"), adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.publicId == '%s')]".formatted(merchant.getPublicId())).exists());

        // No assistants while pending (D21)
        createAssistant(merchantToken, uniqueNic()).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("MERCHANT_NOT_ACTIVE"));

        // Reject needs a reason
        mockMvc.perform(json(withBearer(post("/api/admin/merchants/%s/reject".formatted(merchant.getPublicId())),
                        adminToken), "{}"))
                .andExpect(status().isBadRequest());

        for (int attempt = 1; attempt <= 3; attempt++) {
            reject(adminToken, merchant, "Unreadable document " + attempt).andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("REJECTED"));
            mockMvc.perform(withBearer(get("/api/merchant/application"), merchantToken))
                    .andExpect(jsonPath("$.status").value("REJECTED"))
                    .andExpect(jsonPath("$.statusReason").value("Unreadable document " + attempt))
                    .andExpect(jsonPath("$.attemptsUsed").value(attempt))
                    .andExpect(jsonPath("$.canResubmit").value(attempt < 3));
            if (attempt < 3) {
                resubmit(merchantToken).andExpect(status().isOk())
                        .andExpect(jsonPath("$.status").value("PENDING_APPROVAL"))
                        .andExpect(jsonPath("$.attemptNo").value(attempt + 1));
            }
        }
        resubmit(merchantToken).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("APPLICATION_LIMIT_REACHED"));
        assertThat(reload(merchant).getApplicationAttempts()).isEqualTo(3);

        // A second merchant goes straight through
        User other = registerMerchant();
        approve(adminToken, other).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("ACTIVE"));
        approve(adminToken, other).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("INVALID_STATUS_TRANSITION"));
        createAssistant(tokenFor(other), uniqueNic()).andExpect(status().isCreated());

        assertThat(eventTypes(other)).contains("UserStatusChanged");
        assertThat(auditActions(other)).contains("MERCHANT_APPROVED");
        assertThat(auditActions(merchant)).contains("MERCHANT_REJECTED", "MERCHANT_APPLICATION_RESUBMITTED");
    }

    @Test
    void merchantBanIsSilentForFourteenDaysThenAnnounced() throws Exception {
        User admin = admin();
        String adminToken = tokenFor(admin);
        User merchant = merchant(UserStatus.ACTIVE);
        User assistant = assistant(merchant, Set.of(AssistantPermission.ORDER_VIEW));

        mockMvc.perform(json(withBearer(post("/api/admin/merchants/%s/ban".formatted(merchant.getPublicId())),
                        adminToken), "{\"reason\":\"Counterfeit goods\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("BAN_GRACE"))
                .andExpect(jsonPath("$.banEffectiveAt").isNotEmpty())
                .andExpect(jsonPath("$.statusChangedBy").value(admin.getPublicId()));

        User banned = reload(merchant);
        assertThat(banned.getBanEffectiveAt()).isCloseTo(clock.instant().plus(Duration.ofDays(14)),
                org.assertj.core.api.Assertions.within(1, ChronoUnit.MINUTES));
        assertThat(banned.getTokenVersion()).isEqualTo(1);
        OutboxMessage graceEvent = lastEvent(merchant, "UserStatusChanged");
        assertThat(JsonPath.<String>read(graceEvent.getPayload(), "$.status")).isEqualTo("BAN_GRACE");
        assertThat(JsonPath.<String>read(graceEvent.getPayload(), "$.previousStatus")).isEqualTo("ACTIVE");

        // During the grace period the merchant sees nothing and assistants keep working
        login(merchant.getEmail(), PASSWORD).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.statusReason").doesNotExist());
        login(assistant.getEmail(), PASSWORD).andExpect(status().isOk());
        createAssistant(tokenFor(merchant), uniqueNic()).andExpect(status().isCreated());

        // Day 13: still grace
        clock.advance(Duration.ofDays(13));
        banEnforcementJob.run(); // (other tests' merchants may be due; this one is not)
        assertThat(reload(merchant).getStatus()).isEqualTo(UserStatus.BAN_GRACE);

        // Day 14: announced. The assistant's still-unexpired token is revoked.
        clock.advance(Duration.ofDays(1).plusMinutes(1));
        String assistantToken = read(loginOk(assistant.getEmail(), PASSWORD), "$.accessToken");
        assertThat(banEnforcementJob.run()).isGreaterThanOrEqualTo(1);
        User announced = reload(merchant);
        assertThat(announced.getStatus()).isEqualTo(UserStatus.BANNED);
        assertThat(announced.getBanAnnouncedAt()).isNotNull();
        assertThat(announced.getStatusChangedBy()).isEqualTo("SYSTEM");
        assertThat(banEnforcementJob.run()).isZero(); // idempotent

        login(merchant.getEmail(), PASSWORD).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("BANNED"))
                .andExpect(jsonPath("$.statusReason").value("Counterfeit goods"));
        login(assistant.getEmail(), PASSWORD).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("MERCHANT_BANNED"));
        mockMvc.perform(withBearer(get("/api/users/me"), assistantToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_REVOKED"));

        OutboxMessage bannedEvent = lastEvent(merchant, "UserStatusChanged");
        assertThat(JsonPath.<String>read(bannedEvent.getPayload(), "$.status")).isEqualTo("BANNED");
        assertThat(eventTypes(merchant)).contains("UserSecurityChanged");
        assertThat(eventTypes(assistant)).contains("UserSecurityChanged");
        assertThat(auditActions(merchant)).contains("MERCHANT_BANNED", "MERCHANT_BAN_ENFORCED");

        // Unban restores ACTIVE and lets assistants back in (fresh admin token: 14 days have passed)
        mockMvc.perform(json(withBearer(post("/api/admin/merchants/%s/unban".formatted(merchant.getPublicId())),
                        tokenFor(admin)), "{\"reason\":\"Appeal accepted\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.banEffectiveAt").doesNotExist());
        login(assistant.getEmail(), PASSWORD).andExpect(status().isOk());
    }

    @Test
    void unbanDuringGraceCancelsTheBan() throws Exception {
        String adminToken = tokenFor(admin());
        User merchant = merchant(UserStatus.ACTIVE);
        mockMvc.perform(json(withBearer(post("/api/admin/merchants/%s/ban".formatted(merchant.getPublicId())),
                adminToken), "{\"reason\":\"Mistake\"}")).andExpect(status().isOk());
        mockMvc.perform(json(withBearer(post("/api/admin/merchants/%s/unban".formatted(merchant.getPublicId())),
                adminToken), "{\"reason\":\"Wrong merchant\"}")).andExpect(status().isOk());

        clock.advance(Duration.ofDays(15));
        banEnforcementJob.run();
        assertThat(reload(merchant).getStatus()).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void customerBanIsImmediateAndVisible() throws Exception {
        String adminToken = tokenFor(admin());
        User customer = customer();
        String customerToken = tokenFor(customer);

        mockMvc.perform(json(withBearer(post("/api/admin/customers/%s/ban".formatted(customer.getPublicId())),
                        adminToken), "{\"reason\":\"Payment fraud\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("BANNED"));
        mockMvc.perform(withBearer(get("/api/users/me"), customerToken)).andExpect(status().isUnauthorized());
        login(customer.getEmail(), PASSWORD).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("BANNED"))
                .andExpect(jsonPath("$.statusReason").value("Payment fraud"));

        // A merchant is not a customer: 404 on the customer endpoint
        mockMvc.perform(json(withBearer(post("/api/admin/customers/%s/ban".formatted(
                        merchant(UserStatus.ACTIVE).getPublicId())), adminToken), "{\"reason\":\"x\"}"))
                .andExpect(status().isNotFound());

        mockMvc.perform(json(withBearer(post("/api/admin/customers/%s/unban".formatted(customer.getPublicId())),
                        adminToken), "{\"reason\":\"Cleared\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));
        assertThat(reload(customer).getTokenVersion()).isEqualTo(2);
    }

    @Test
    void superAdminManagesAdminsAndCannotBeTargeted() throws Exception {
        User superAdmin = superAdmin();
        String superToken = tokenFor(superAdmin);
        String email = uniqueEmail("new-admin");

        String created = mockMvc.perform(json(withBearer(post("/api/super-admin/admins"), superToken), """
                        {"email":"%s","firstName":"Ada","lastName":"Admin","nic":"%s","phone":"%s",
                         "temporaryPassword":"Temporary-Pass-123"}
                        """.formatted(email, uniqueNic(), uniquePhone())))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("ROLE_ADMIN"))
                .andExpect(jsonPath("$.mustChangePassword").value(true))
                .andReturn().getResponse().getContentAsString();
        String adminId = read(created, "$.publicId");

        login(email, "Temporary-Pass-123").andExpect(status().isOk())
                .andExpect(jsonPath("$.mustChangePassword").value(true));

        mockMvc.perform(json(withBearer(post("/api/super-admin/admins/%s/ban".formatted(adminId)), superToken),
                        "{\"reason\":\"Abuse of power\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("BANNED"));
        login(email, "Temporary-Pass-123").andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Your account has been banned. Reason: Abuse of power"));

        mockMvc.perform(json(withBearer(post("/api/super-admin/admins/%s/unban".formatted(adminId)), superToken),
                        "{\"reason\":\"Reinstated\"}"))
                .andExpect(status().isOk());
        login(email, "Temporary-Pass-123").andExpect(status().isOk());

        // The super admin is not an admin target
        mockMvc.perform(json(withBearer(post("/api/super-admin/admins/%s/ban".formatted(superAdmin.getPublicId())),
                        superToken), "{\"reason\":\"x\"}"))
                .andExpect(status().isNotFound());

        List<AuditLogEntry> audit = auditLogRepository.findAllByTargetTypeAndTargetIdOrderByIdAsc(
                AuditService.TARGET_USER, adminId);
        assertThat(audit).extracting(AuditLogEntry::getAction)
                .containsExactly("ADMIN_CREATED", "ADMIN_BANNED", "ADMIN_UNBANNED");
        assertThat(audit).allSatisfy(entry -> {
            assertThat(entry.getActorPublicId()).isEqualTo(superAdmin.getPublicId());
            assertThat(entry.getAfterState()).doesNotContain("Temporary-Pass-123").doesNotContain("argon2");
        });
    }

    @Test
    void adminUserSearchFiltersAndValidatesSort() throws Exception {
        String adminToken = tokenFor(admin());
        User customer = customer();

        mockMvc.perform(withBearer(get("/api/admin/users?role=ROLE_CUSTOMER&q=" + customer.getPublicId()),
                        adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].nic").value(customer.getNic()));
        mockMvc.perform(withBearer(get("/api/admin/users?q=%25"), adminToken)).andExpect(status().isOk());
        mockMvc.perform(withBearer(get("/api/admin/users?sort=passwordHash,asc"), adminToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_SORT"));
        mockMvc.perform(withBearer(get("/api/admin/users?size=1000"), adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size").value(100));
    }

    // ------------------------------------------------------------------------------------------------- helpers

    private User registerMerchant() throws Exception {
        String email = uniqueEmail("applicant");
        mockMvc.perform(json(post("/api/users/register/merchant"), """
                        {"email":"%s","password":"%s","firstName":"Ann","lastName":"Applicant","nic":"%s",
                         "phone":"%s","businessName":"Ann Crafts","documentKeys":["br/ann-1.pdf"]}
                        """.formatted(email, PASSWORD, uniqueNic(), uniquePhone())))
                .andExpect(status().isCreated());
        return userRepository.findByEmail(email).orElseThrow();
    }

    private org.springframework.test.web.servlet.ResultActions reject(String token, User merchant, String reason)
            throws Exception {
        return mockMvc.perform(json(withBearer(post("/api/admin/merchants/%s/reject".formatted(
                merchant.getPublicId())), token), "{\"reason\":\"%s\"}".formatted(reason)));
    }

    private org.springframework.test.web.servlet.ResultActions approve(String token, User merchant)
            throws Exception {
        return mockMvc.perform(withBearer(post("/api/admin/merchants/%s/approve".formatted(merchant.getPublicId())),
                token));
    }

    private org.springframework.test.web.servlet.ResultActions resubmit(String token) throws Exception {
        return mockMvc.perform(json(withBearer(post("/api/merchant/application/resubmit"), token),
                "{\"businessName\":\"Ann Crafts\",\"documentKeys\":[\"br/ann-2.pdf\"]}"));
    }

    private org.springframework.test.web.servlet.ResultActions createAssistant(String token, String nic)
            throws Exception {
        return mockMvc.perform(json(withBearer(post("/api/merchant/owner/assistants"), token), """
                {"email":"%s","firstName":"Asha","lastName":"Assistant","nic":"%s","phone":"%s",
                 "permissions":["ORDER_VIEW"],"temporaryPassword":"Temporary-Pass-123"}
                """.formatted(uniqueEmail("assistant"), nic, uniquePhone())));
    }

    private List<String> eventTypes(User user) {
        return outboxRepository.findAllByAggregateIdOrderByIdAsc(user.getId()).stream()
                .map(OutboxMessage::getEventType).toList();
    }

    private OutboxMessage lastEvent(User user, String type) {
        return outboxRepository.findAllByAggregateIdOrderByIdAsc(user.getId()).stream()
                .filter(m -> m.getEventType().equals(type))
                .reduce((first, second) -> second).orElseThrow();
    }

    private List<String> auditActions(User user) {
        return auditLogRepository.findAllByTargetTypeAndTargetIdOrderByIdAsc(AuditService.TARGET_USER,
                user.getPublicId()).stream().map(AuditLogEntry::getAction).toList();
    }
}
