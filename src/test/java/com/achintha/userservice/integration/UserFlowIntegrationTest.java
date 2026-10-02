package com.achintha.userservice.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.achintha.userservice.common.PublicIdGenerator;
import com.achintha.userservice.support.IntegrationTest;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

/** Registration, profile and address flows end to end. */
class UserFlowIntegrationTest extends IntegrationTest {

    @Test
    void registerCustomerLoginAndManageProfileAndAddresses() throws Exception {
        String email = uniqueEmail("Jane.Doe");
        String nic = uniqueNic().toLowerCase();
        mockMvc.perform(json(post("/api/users/register/customer"), """
                        {"email":"%s","password":"%s","firstName":"Jane","lastName":"<b>Doe</b>",
                         "nic":"%s","phone":"+94771234567"}
                        """.formatted(email, PASSWORD, nic)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.publicId").isNotEmpty())
                .andExpect(jsonPath("$.email").value(email.toLowerCase()))
                .andExpect(jsonPath("$.role").value("ROLE_CUSTOMER"))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.lastName").value("Doe"))
                .andExpect(jsonPath("$.nic").value(nic.toUpperCase()))
                .andExpect(jsonPath("$.id").doesNotExist())
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        User stored = userRepository.findByEmail(email.toLowerCase()).orElseThrow();
        assertThat(PublicIdGenerator.isValid(stored.getPublicId())).isTrue();
        assertThat(stored.getPasswordHash()).startsWith("{argon2}");

        // Duplicate email, case-insensitive
        mockMvc.perform(json(post("/api/users/register/customer"), """
                        {"email":"%s","password":"%s","firstName":"Jane","lastName":"Doe",
                         "nic":"%s","phone":"+94771234567"}
                        """.formatted(email.toUpperCase(), PASSWORD, uniqueNic())))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("EMAIL_ALREADY_EXISTS"));

        String body = loginOk(email, PASSWORD);
        String token = read(body, "$.accessToken");

        mockMvc.perform(withBearer(get("/api/users/me"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email.toLowerCase()))
                .andExpect(jsonPath("$.mustChangePassword").value(false));

        // PUT /me ignores email, role and status in the body
        mockMvc.perform(json(withBearer(put("/api/users/me"), token), """
                        {"firstName":"Janet","lastName":"Smith","phone":"+94770000001",
                         "email":"hacker@example.com","role":"ROLE_ADMIN","status":"BANNED"}
                        """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("Janet"))
                .andExpect(jsonPath("$.phone").value("+94770000001"))
                .andExpect(jsonPath("$.email").value(email.toLowerCase()))
                .andExpect(jsonPath("$.role").value("ROLE_CUSTOMER"));

        // Addresses: create, list (paged), get, update, delete
        String address = mockMvc.perform(json(withBearer(post("/api/users/me/addresses"), token), """
                        {"recipientName":"Jane Doe","phone":"+94771234567","line1":"1 Main St",
                         "city":"Colombo","district":"Colombo","postalCode":"00100"}
                        """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.publicId").isNotEmpty())
                .andExpect(jsonPath("$.country").value("Sri Lanka"))
                .andReturn().getResponse().getContentAsString();
        String addressId = read(address, "$.publicId");
        assertThat(addressId).startsWith("ADR-");

        mockMvc.perform(withBearer(get("/api/users/me/addresses"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].district").value("Colombo"));

        mockMvc.perform(json(withBearer(put("/api/users/me/addresses/" + addressId), token), """
                        {"recipientName":"Jane D","phone":"+94771234567","line1":"2 Main St",
                         "city":"Kandy","district":"Kandy","postalCode":"20000","country":"LK"}
                        """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.city").value("Kandy"));

        // Another user cannot see it (404, not 403)
        String otherToken = tokenFor(customer());
        mockMvc.perform(withBearer(get("/api/users/me/addresses/" + addressId), otherToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(withBearer(delete("/api/users/me/addresses/" + addressId), otherToken))
                .andExpect(status().isNotFound());

        mockMvc.perform(withBearer(delete("/api/users/me/addresses/" + addressId), token))
                .andExpect(status().isNoContent());
        mockMvc.perform(withBearer(get("/api/users/me/addresses/" + addressId), token))
                .andExpect(status().isNotFound());
    }

    @Test
    void registerMerchantStartsPendingWithStoreId() throws Exception {
        String email = uniqueEmail("merchant");
        mockMvc.perform(json(post("/api/users/register/merchant"), """
                        {"email":"%s","password":"%s","firstName":"Mo","lastName":"Merchant",
                         "nic":"200012345678","phone":"+94771234500",
                         "businessName":"Mo's <script>alert(1)</script>Store","documentKeys":["docs/br-1.pdf"]}
                        """.formatted(email, PASSWORD)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("ROLE_MERCHANT"))
                .andExpect(jsonPath("$.status").value("PENDING_APPROVAL"))
                .andExpect(jsonPath("$.storeId").doesNotExist());

        User merchant = userRepository.findByEmail(email).orElseThrow();
        assertThat(merchant.getStatus()).isEqualTo(UserStatus.PENDING_APPROVAL);
        assertThat(merchant.getStoreId()).isNotNull();
        assertThat(merchant.getApplicationAttempts()).isEqualTo(1);

        String token = read(loginOk(email, PASSWORD), "$.accessToken");
        mockMvc.perform(withBearer(get("/api/merchant/application"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.businessName").value("Mo's Store"))
                .andExpect(jsonPath("$.documentKeys[0]").value("docs/br-1.pdf"))
                .andExpect(jsonPath("$.attemptsUsed").value(1))
                .andExpect(jsonPath("$.maxAttempts").value(3))
                .andExpect(jsonPath("$.canResubmit").value(false));
    }

    @Test
    void rejectsInvalidRegistration() throws Exception {
        mockMvc.perform(json(post("/api/users/register/customer"), """
                        {"email":"not-an-email","password":"password1234","firstName":"","lastName":"Doe",
                         "nic":"12345","phone":"0771234567"}
                        """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'email')]").exists())
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'password')]").exists())
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'firstName')]").exists())
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'nic')]").exists())
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'phone')]").exists());

        // The old generic endpoint is gone (deny-by-default: no anonymous access to unknown paths)
        mockMvc.perform(json(post("/api/users/register"), "{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointsRequireValidToken() throws Exception {
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

        mockMvc.perform(withBearer(get("/api/users/me"), "not.a.jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void jwksIsPublicAndCacheable() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "max-age=300, public"))
                .andExpect(jsonPath("$.keys", hasSize(1)))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].kid").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist());
    }

    @Test
    void internalDocsAreNotPublished() throws Exception {
        String docs = mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(docs).contains("/api/auth/login").doesNotContain("/internal/");
        assertThat(docs.toLowerCase()).doesNotContain("seller").doesNotContain("shop");
    }
}
