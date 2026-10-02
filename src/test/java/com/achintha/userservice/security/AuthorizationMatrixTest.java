package com.achintha.userservice.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;

import com.achintha.userservice.support.IntegrationTest;
import com.achintha.userservice.user.AssistantPermission;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserStatus;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Role-by-endpoint authorization matrix (section 11): every endpoint is called by every role and anonymously.
 * "Allowed" calls target harmless or non-existent resources, so 404 (and the odd 400/409 from business rules)
 * proves the call got past authorization; 401/403 prove it did not.
 */
class AuthorizationMatrixTest extends IntegrationTest {

    enum Who { ANONYMOUS, CUSTOMER, MERCHANT, ASSISTANT, ADMIN, SUPER_ADMIN, SERVICE }

    private static final String MISSING_USER = "USR-2610-ZZZZZZ";
    private static final String MISSING_ADDRESS = "ADR-2610-ZZZZZZ";

    private static Map<Who, String> tokens;
    private static User customerFixture;

    @BeforeEach
    void fixtures() {
        if (tokens != null) {
            return;
        }
        customerFixture = customer();
        User merchant = merchant(UserStatus.ACTIVE);
        tokens = new EnumMap<>(Who.class);
        tokens.put(Who.CUSTOMER, tokenFor(customerFixture));
        tokens.put(Who.MERCHANT, tokenFor(merchant));
        tokens.put(Who.ASSISTANT, tokenFor(assistant(merchant, EnumSet.allOf(AssistantPermission.class))));
        tokens.put(Who.ADMIN, tokenFor(admin()));
        tokens.put(Who.SUPER_ADMIN, tokenFor(superAdmin()));
        tokens.put(Who.SERVICE, serviceToken());
    }

    record Endpoint(String name, HttpMethod method, String path, Supplier<String> body, Map<Who, Integer> allowed) {

        @Override
        public String toString() {
            return method + " " + path;
        }
    }

    static Stream<Arguments> matrix() {
        List<Arguments> arguments = new ArrayList<>();
        for (Endpoint endpoint : endpoints()) {
            for (Who who : Who.values()) {
                int expected = endpoint.allowed().getOrDefault(who, who == Who.ANONYMOUS ? 401 : 403);
                arguments.add(Arguments.of(endpoint, who, expected));
            }
        }
        return arguments.stream();
    }

    @ParameterizedTest(name = "{0} as {1} -> {2}")
    @MethodSource("matrix")
    void endpointAnswersAsExpected(Endpoint endpoint, Who who, int expected) throws Exception {
        String path = endpoint.path()
                .replace("{customerId}", customerFixture.getId().toString())
                .replace("{missingUuid}", "00000000-0000-0000-0000-000000000000");
        MockHttpServletRequestBuilder request = request(endpoint.method(), path);
        if (endpoint.body() != null) {
            request = json(request, endpoint.body().get());
        }
        MockHttpServletResponse response = mockMvc.perform(withBearer(request, tokens.get(who)))
                .andReturn().getResponse();
        Assertions.assertThat(response.getStatus())
                .as("%s as %s: %s", endpoint, who, response.getContentAsString())
                .isEqualTo(expected);
    }

    // ------------------------------------------------------------------------------------------------ endpoints

    private static List<Endpoint> endpoints() {
        Map<Who, Integer> everyone = only(200, Who.values());
        Map<Who, Integer> users = only(200, Who.CUSTOMER, Who.MERCHANT, Who.ASSISTANT, Who.ADMIN, Who.SUPER_ADMIN);
        Map<Who, Integer> admins = only(200, Who.ADMIN, Who.SUPER_ADMIN);
        Map<Who, Integer> superAdmin = only(200, Who.SUPER_ADMIN);
        Map<Who, Integer> owner = only(200, Who.MERCHANT);
        Map<Who, Integer> service = only(200, Who.SERVICE);
        Supplier<String> reason = () -> "{\"reason\":\"matrix test\"}";

        return List.of(
                // Public
                new Endpoint("jwks", HttpMethod.GET, "/.well-known/jwks.json", null, everyone),
                new Endpoint("register customer", HttpMethod.POST, "/api/users/register/customer",
                        AuthorizationMatrixTest::customerRegistration, only(201, Who.values())),
                new Endpoint("register merchant", HttpMethod.POST, "/api/users/register/merchant",
                        AuthorizationMatrixTest::merchantRegistration, only(201, Who.values())),
                new Endpoint("login", HttpMethod.POST, "/api/auth/login",
                        () -> "{\"email\":\"%s\",\"password\":\"Wrong-Password-1\"}".formatted(uniqueEmail("nobody")),
                        only(401, Who.values())),
                new Endpoint("refresh", HttpMethod.POST, "/api/auth/refresh",
                        () -> "{\"refreshToken\":\"not-a-refresh-token\"}", only(401, Who.values())),
                new Endpoint("service token", HttpMethod.POST, "/internal/auth/service-token",
                        () -> "{\"clientId\":\"order-service\",\"clientSecret\":\"" + SERVICE_CLIENT_SECRET + "\"}",
                        everyone),

                // Any signed-in user
                new Endpoint("logout", HttpMethod.POST, "/api/auth/logout",
                        () -> "{\"refreshToken\":\"unknown\"}", only(204, users.keySet())),
                new Endpoint("change password", HttpMethod.POST, "/api/auth/change-password",
                        () -> "{\"currentPassword\":\"Not-The-Password-1\",\"newPassword\":\"Another-Passphrase-9\"}",
                        only(400, users.keySet())),
                new Endpoint("me", HttpMethod.GET, "/api/users/me", null, users),
                new Endpoint("update me", HttpMethod.PUT, "/api/users/me",
                        () -> "{\"firstName\":\"Matrix\",\"lastName\":\"User\"}", users),
                new Endpoint("list addresses", HttpMethod.GET, "/api/users/me/addresses", null, users),
                new Endpoint("add address", HttpMethod.POST, "/api/users/me/addresses",
                        AuthorizationMatrixTest::address, only(201, users.keySet())),
                new Endpoint("get address", HttpMethod.GET, "/api/users/me/addresses/" + MISSING_ADDRESS, null,
                        only(404, users.keySet())),
                new Endpoint("update address", HttpMethod.PUT, "/api/users/me/addresses/" + MISSING_ADDRESS,
                        AuthorizationMatrixTest::address, only(404, users.keySet())),
                new Endpoint("delete address", HttpMethod.DELETE, "/api/users/me/addresses/" + MISSING_ADDRESS,
                        null, only(404, users.keySet())),

                // Merchant (owner only, assistants refused)
                new Endpoint("application", HttpMethod.GET, "/api/merchant/application", null,
                        only(404, Who.MERCHANT)),
                new Endpoint("resubmit", HttpMethod.POST, "/api/merchant/application/resubmit",
                        () -> "{\"businessName\":\"Matrix\",\"documentKeys\":[\"k1\"]}", only(409, Who.MERCHANT)),
                new Endpoint("list assistants", HttpMethod.GET, "/api/merchant/owner/assistants", null, owner),
                new Endpoint("create assistant", HttpMethod.POST, "/api/merchant/owner/assistants",
                        AuthorizationMatrixTest::assistantCreation, only(201, Who.MERCHANT)),
                new Endpoint("get assistant", HttpMethod.GET, "/api/merchant/owner/assistants/" + MISSING_USER,
                        null, only(404, Who.MERCHANT)),
                new Endpoint("assistant permissions", HttpMethod.PUT,
                        "/api/merchant/owner/assistants/" + MISSING_USER + "/permissions",
                        () -> "{\"permissions\":[\"ORDER_VIEW\"]}", only(404, Who.MERCHANT)),
                new Endpoint("ban assistant", HttpMethod.POST,
                        "/api/merchant/owner/assistants/" + MISSING_USER + "/ban", reason, only(404, Who.MERCHANT)),
                new Endpoint("unban assistant", HttpMethod.POST,
                        "/api/merchant/owner/assistants/" + MISSING_USER + "/unban", reason,
                        only(404, Who.MERCHANT)),
                new Endpoint("remove assistant", HttpMethod.POST,
                        "/api/merchant/owner/assistants/" + MISSING_USER + "/remove", reason,
                        only(404, Who.MERCHANT)),

                // Admin
                new Endpoint("search users", HttpMethod.GET, "/api/admin/users", null, admins),
                new Endpoint("view user", HttpMethod.GET, "/api/admin/users/" + MISSING_USER, null,
                        only(404, Who.ADMIN, Who.SUPER_ADMIN)),
                new Endpoint("admin bans assistant", HttpMethod.POST,
                        "/api/admin/users/" + MISSING_USER + "/assistant-ban", reason,
                        only(404, Who.ADMIN, Who.SUPER_ADMIN)),
                new Endpoint("pending merchants", HttpMethod.GET, "/api/admin/merchants/pending", null, admins),
                new Endpoint("approve", HttpMethod.POST, "/api/admin/merchants/" + MISSING_USER + "/approve",
                        () -> "{}", only(404, Who.ADMIN, Who.SUPER_ADMIN)),
                new Endpoint("reject", HttpMethod.POST, "/api/admin/merchants/" + MISSING_USER + "/reject",
                        reason, only(404, Who.ADMIN, Who.SUPER_ADMIN)),
                new Endpoint("ban merchant", HttpMethod.POST, "/api/admin/merchants/" + MISSING_USER + "/ban",
                        reason, only(404, Who.ADMIN, Who.SUPER_ADMIN)),
                new Endpoint("unban merchant", HttpMethod.POST, "/api/admin/merchants/" + MISSING_USER + "/unban",
                        reason, only(404, Who.ADMIN, Who.SUPER_ADMIN)),
                new Endpoint("ban customer", HttpMethod.POST, "/api/admin/customers/" + MISSING_USER + "/ban",
                        reason, only(404, Who.ADMIN, Who.SUPER_ADMIN)),
                new Endpoint("unban customer", HttpMethod.POST, "/api/admin/customers/" + MISSING_USER + "/unban",
                        reason, only(404, Who.ADMIN, Who.SUPER_ADMIN)),

                // Super admin
                new Endpoint("list admins", HttpMethod.GET, "/api/super-admin/admins", null, superAdmin),
                new Endpoint("create admin", HttpMethod.POST, "/api/super-admin/admins",
                        AuthorizationMatrixTest::adminCreation, only(201, Who.SUPER_ADMIN)),
                new Endpoint("ban admin", HttpMethod.POST, "/api/super-admin/admins/" + MISSING_USER + "/ban",
                        reason, only(404, Who.SUPER_ADMIN)),
                new Endpoint("unban admin", HttpMethod.POST, "/api/super-admin/admins/" + MISSING_USER + "/unban",
                        reason, only(404, Who.SUPER_ADMIN)),

                // Internal (service tokens only)
                new Endpoint("security state", HttpMethod.GET, "/internal/users/{customerId}/security-state", null,
                        service),
                new Endpoint("contact", HttpMethod.GET, "/internal/users/{customerId}/contact", null, service),
                new Endpoint("internal address", HttpMethod.GET,
                        "/internal/users/{customerId}/addresses/" + MISSING_ADDRESS, null, only(404, Who.SERVICE)),
                new Endpoint("unknown user state", HttpMethod.GET, "/internal/users/{missingUuid}/security-state",
                        null, only(404, Who.SERVICE)),

                // Prefix rules and deny-by-default
                new Endpoint("customer prefix", HttpMethod.GET, "/api/customer/anything", null,
                        only(404, Who.CUSTOMER)),
                new Endpoint("unknown prefix", HttpMethod.GET, "/api/unknown", null, Map.of()),
                new Endpoint("actuator env", HttpMethod.GET, "/actuator/env", null, Map.of()));
    }

    private static Map<Who, Integer> only(int status, Who... who) {
        return only(status, List.of(who));
    }

    private static Map<Who, Integer> only(int status, Iterable<Who> who) {
        Map<Who, Integer> map = new EnumMap<>(Who.class);
        who.forEach(w -> map.put(w, status));
        return map;
    }

    // --------------------------------------------------------------------------------------------- request bodies

    private static String customerRegistration() {
        return """
                {"email":"%s","password":"%s","firstName":"Matrix","lastName":"Customer","nic":"%s","phone":"%s"}
                """.formatted(uniqueEmail("matrix-customer"), PASSWORD, uniqueNic(), uniquePhone());
    }

    private static String merchantRegistration() {
        return """
                {"email":"%s","password":"%s","firstName":"Matrix","lastName":"Merchant","nic":"%s","phone":"%s",
                 "businessName":"Matrix Store","documentKeys":["doc-1"]}
                """.formatted(uniqueEmail("matrix-merchant"), PASSWORD, uniqueNic(), uniquePhone());
    }

    private static String assistantCreation() {
        return """
                {"email":"%s","firstName":"Matrix","lastName":"Assistant","nic":"%s","phone":"%s",
                 "permissions":["ORDER_VIEW"],"temporaryPassword":"Temporary-Pass-123"}
                """.formatted(uniqueEmail("matrix-assistant"), uniqueNic(), uniquePhone());
    }

    private static String adminCreation() {
        return """
                {"email":"%s","firstName":"Matrix","lastName":"Admin","nic":"%s","phone":"%s",
                 "temporaryPassword":"Temporary-Pass-123"}
                """.formatted(uniqueEmail("matrix-admin"), uniqueNic(), uniquePhone());
    }

    private static String address() {
        return """
                {"recipientName":"Matrix","phone":"+94771234567","line1":"1 Test Road","city":"Galle",
                 "district":"Galle","postalCode":"80000"}
                """;
    }
}
