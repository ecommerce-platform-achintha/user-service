package com.achintha.userservice.assistant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.achintha.userservice.support.IntegrationTest;
import com.achintha.userservice.user.AssistantStatus;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.ResultActions;

/** Owner-side assistant management: NIC rule (section 13, point 5), store scoping (BOLA) and token revocation. */
class AssistantManagementTest extends IntegrationTest {

    @Test
    void createsAssistantWithForcedPasswordChangeAndMaskedNic() throws Exception {
        User merchant = merchant(UserStatus.ACTIVE);
        String nic = uniqueNic();
        String email = uniqueEmail("asst");

        create(tokenFor(merchant), email, nic, "[\"ORDER_VIEW\",\"ORDER_SHIP\"]")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.assistantStatus").value("ACTIVE"))
                .andExpect(jsonPath("$.permissions[0]").value("ORDER_SHIP"))
                .andExpect(jsonPath("$.nic").value("*******" + nic.substring(7)))
                .andExpect(jsonPath("$.mustChangePassword").value(true));

        User assistant = userRepository.findByEmail(email).orElseThrow();
        assertThat(assistant.getStoreId()).isEqualTo(merchant.getStoreId());
        String body = loginOk(email, "Temporary-Pass-123");
        assertThat(read(body, "$.mustChangePassword")).isEqualTo("true");
        mockMvc.perform(withBearer(get("/api/users/me"), read(body, "$.accessToken")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PASSWORD_CHANGE_REQUIRED"));
    }

    @Test
    void assistantNicBelongsToOneStoreAtATime() throws Exception {
        String storeA = tokenFor(merchant(UserStatus.ACTIVE));
        String storeB = tokenFor(merchant(UserStatus.ACTIVE));
        String nic = uniqueNic();

        String created = create(storeA, uniqueEmail("asst"), nic, "[\"ORDER_VIEW\"]")
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String assistantId = read(created, "$.publicId");

        // Same NIC in another store: refused, also in the other NIC format letter case
        create(storeB, uniqueEmail("asst"), nic.toLowerCase(), "[\"ORDER_VIEW\"]")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("NIC_ALREADY_ASSIGNED"));

        // Merchant ban releases the NIC
        mockMvc.perform(json(withBearer(post("/api/merchant/owner/assistants/%s/ban".formatted(assistantId)),
                        storeA), "{\"reason\":\"Rude to customers\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assistantStatus").value("BANNED_BY_MERCHANT"));
        String inStoreB = create(storeB, uniqueEmail("asst"), nic, "[\"ORDER_VIEW\"]")
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();

        // ...so store A cannot reactivate its banned assistant while store B holds it
        mockMvc.perform(json(withBearer(post("/api/merchant/owner/assistants/%s/unban".formatted(assistantId)),
                        storeA), "{\"reason\":\"Second chance\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("NIC_ALREADY_ASSIGNED"));

        // Store B removes theirs: released again
        mockMvc.perform(json(withBearer(post("/api/merchant/owner/assistants/%s/remove".formatted(
                        read(inStoreB, "$.publicId"))), storeB), "{\"reason\":\"Left\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assistantStatus").value("REMOVED"));
        mockMvc.perform(json(withBearer(post("/api/merchant/owner/assistants/%s/unban".formatted(assistantId)),
                        storeA), "{\"reason\":\"Second chance\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assistantStatus").value("ACTIVE"));
    }

    @Test
    void adminBanBlocksTheNicPermanently() throws Exception {
        String storeA = tokenFor(merchant(UserStatus.ACTIVE));
        String storeB = tokenFor(merchant(UserStatus.ACTIVE));
        String nic = uniqueNic();
        String assistantId = read(create(storeA, uniqueEmail("asst"), nic, "[\"ORDER_VIEW\"]")
                .andReturn().getResponse().getContentAsString(), "$.publicId");

        mockMvc.perform(json(withBearer(post("/api/admin/users/%s/assistant-ban".formatted(assistantId)),
                        tokenFor(admin())), "{\"reason\":\"Theft\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assistantStatus").value("BANNED_BY_ADMIN"));

        create(storeB, uniqueEmail("asst"), nic, "[\"ORDER_VIEW\"]")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("NIC_ALREADY_ASSIGNED"));
        // The merchant can no longer change an admin-banned assistant
        mockMvc.perform(json(withBearer(post("/api/merchant/owner/assistants/%s/remove".formatted(assistantId)),
                        storeA), "{\"reason\":\"x\"}"))
                .andExpect(status().isConflict());
    }

    @Test
    void foreignAssistantsAreNotFound() throws Exception {
        String storeA = tokenFor(merchant(UserStatus.ACTIVE));
        User merchantB = merchant(UserStatus.ACTIVE);
        String assistantOfB = assistant(merchantB, java.util.Set.of()).getPublicId();

        mockMvc.perform(withBearer(get("/api/merchant/owner/assistants/" + assistantOfB), storeA))
                .andExpect(status().isNotFound());
        mockMvc.perform(json(withBearer(put("/api/merchant/owner/assistants/%s/permissions".formatted(assistantOfB)),
                        storeA), "{\"permissions\":[\"ORDER_VIEW\"]}"))
                .andExpect(status().isNotFound());
        mockMvc.perform(json(withBearer(post("/api/merchant/owner/assistants/%s/ban".formatted(assistantOfB)),
                        storeA), "{\"reason\":\"x\"}"))
                .andExpect(status().isNotFound());
        mockMvc.perform(withBearer(get("/api/merchant/owner/assistants"), storeA))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.publicId == '%s')]".formatted(assistantOfB)).doesNotExist());
        assertThat(reload(userRepository.findByPublicId(assistantOfB).orElseThrow()).getAssistantStatus())
                .isEqualTo(AssistantStatus.ACTIVE);
    }

    @Test
    void permissionChangeRevokesTheAssistantsTokens() throws Exception {
        User merchant = merchant(UserStatus.ACTIVE);
        User assistant = assistant(merchant, java.util.Set.of());
        String assistantToken = tokenFor(assistant);
        mockMvc.perform(withBearer(get("/api/users/me"), assistantToken)).andExpect(status().isOk());

        mockMvc.perform(json(withBearer(put("/api/merchant/owner/assistants/%s/permissions".formatted(
                        assistant.getPublicId())), tokenFor(merchant)), "{\"permissions\":[\"STOCK_EDIT\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permissions[0]").value("STOCK_EDIT"));

        mockMvc.perform(withBearer(get("/api/users/me"), assistantToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_REVOKED"));
        String refreshed = loginOk(assistant.getEmail(), PASSWORD);
        mockMvc.perform(withBearer(get("/api/users/me"), read(refreshed, "$.accessToken")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permissions[0]").value("STOCK_EDIT"));
    }

    @Test
    void assistantsCannotManageAssistants() throws Exception {
        User merchant = merchant(UserStatus.ACTIVE);
        String assistantToken = tokenFor(assistant(merchant, java.util.EnumSet.allOf(
                com.achintha.userservice.user.AssistantPermission.class)));

        mockMvc.perform(withBearer(get("/api/merchant/owner/assistants"), assistantToken))
                .andExpect(status().isForbidden());
        create(assistantToken, uniqueEmail("asst"), uniqueNic(), "[\"ORDER_VIEW\"]")
                .andExpect(status().isForbidden());
    }

    private ResultActions create(String token, String email, String nic, String permissions) throws Exception {
        return mockMvc.perform(json(withBearer(post("/api/merchant/owner/assistants"), token), """
                {"email":"%s","firstName":"Asha","lastName":"Assistant","nic":"%s","phone":"%s",
                 "permissions":%s,"temporaryPassword":"Temporary-Pass-123"}
                """.formatted(email, nic, uniquePhone(), permissions)));
    }
}
