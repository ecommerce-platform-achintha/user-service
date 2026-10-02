package com.achintha.userservice.support;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.achintha.userservice.security.JwtService;
import com.achintha.userservice.user.AssistantPermission;
import com.achintha.userservice.user.AssistantStatus;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserAccountFactory;
import com.achintha.userservice.user.UserRepository;
import com.achintha.userservice.user.UserStatus;
import com.jayway.jsonpath.JsonPath;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Base class of the integration tests: the full application against a real PostgreSQL (Testcontainers, one container
 * for the whole test run, so the Spring context is cached and shared). Schedulers are off; tests call the jobs
 * directly. The clock is a {@link MutableClock}.
 */
@SpringBootTest(properties = {
        "spring.cloud.config.enabled=false",
        "eureka.client.enabled=false",
        "app.scheduling.enabled=false",
        // Tests sign in many times from 127.0.0.1; IP throttling has its own test
        "auth.ip-max-failed-logins=10000",
        "security.internal.clients[0].client-id=order-service",
        "security.internal.clients[0].client-secret=" + IntegrationTest.SERVICE_CLIENT_SECRET,
        "bootstrap.super-admin.email=" + IntegrationTest.SUPER_ADMIN_EMAIL,
        "bootstrap.super-admin.initial-password=" + IntegrationTest.SUPER_ADMIN_PASSWORD
})
@AutoConfigureMockMvc
@Import(IntegrationTest.ClockConfig.class)
public abstract class IntegrationTest {

    public static final String PASSWORD = "Correct-Horse-Battery-9";
    public static final String SERVICE_CLIENT_SECRET = "test-order-service-secret-123456";
    public static final String SUPER_ADMIN_EMAIL = "root@marketplace.test";
    public static final String SUPER_ADMIN_PASSWORD = "Bootstrap-Pass-2026!";

    private static final AtomicLong SEQUENCE = new AtomicLong(ThreadLocalRandom.current().nextLong(1_000_000L));

    private static final PostgreSQLContainer POSTGRES = SharedPostgres.CONTAINER;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("security.jwt.signing.private-key", () -> TestKeys.PRIVATE_PEM);
        registry.add("security.jwt.signing.public-key", () -> TestKeys.PUBLIC_PEM);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class ClockConfig {

        @Bean
        @Primary
        MutableClock mutableClock() {
            return new MutableClock();
        }
    }

    @Autowired
    protected MockMvc mockMvc;
    @Autowired
    protected UserRepository userRepository;
    @Autowired
    protected UserAccountFactory accountFactory;
    @Autowired
    protected JwtService jwtService;
    @Autowired
    protected TransactionTemplate transactionTemplate;
    @Autowired
    protected MutableClock clock;

    @AfterEach
    void resetClock() {
        clock.reset();
    }

    // -------------------------------------------------------------------------------------------- unique test data

    protected static String uniqueEmail(String prefix) {
        return prefix + "-" + SEQUENCE.incrementAndGet() + "@example.test";
    }

    /** Old-format NIC: 9 digits + V. */
    protected static String uniqueNic() {
        return String.format("%09dV", SEQUENCE.incrementAndGet() % 1_000_000_000L);
    }

    protected static String uniquePhone() {
        return String.format("+9477%07d", SEQUENCE.incrementAndGet() % 10_000_000L);
    }

    // ------------------------------------------------------------------------------------------------- fixtures

    /** Inserts a user directly (no events, no API), with {@link #PASSWORD}. */
    protected User createUser(Role role, UserStatus status, Consumer<User> customizer) {
        return transactionTemplate.execute(tx -> {
            User user = accountFactory.newUser(role, status, uniqueEmail(role.name().toLowerCase()), PASSWORD,
                    "Test", role.name(), role == Role.ROLE_SUPER_ADMIN ? null : uniqueNic(),
                    role.requiresPhone() ? uniquePhone() : null, "TEST");
            if (role == Role.ROLE_MERCHANT) {
                user.setStoreId(UUID.randomUUID());
                user.setApplicationAttempts(1);
            }
            customizer.accept(user);
            return userRepository.saveAndFlush(user);
        });
    }

    protected User customer() {
        return createUser(Role.ROLE_CUSTOMER, UserStatus.ACTIVE, u -> { });
    }

    protected User merchant(UserStatus status) {
        return createUser(Role.ROLE_MERCHANT, status, u -> { });
    }

    protected User admin() {
        return createUser(Role.ROLE_ADMIN, UserStatus.ACTIVE, u -> { });
    }

    protected User assistant(User merchant, Set<AssistantPermission> permissions) {
        return createUser(Role.ROLE_ASSISTANT, UserStatus.ACTIVE, u -> {
            u.setStoreId(merchant.getStoreId());
            u.setAssistantStatus(AssistantStatus.ACTIVE);
            u.setPermissions(permissions.isEmpty() ? EnumSet.noneOf(AssistantPermission.class)
                    : EnumSet.copyOf(permissions));
        });
    }

    /** The bootstrapped super admin, with the forced password change already done. */
    protected User superAdmin() {
        return transactionTemplate.execute(tx -> {
            User superAdmin = userRepository.findByEmail(SUPER_ADMIN_EMAIL).orElseThrow();
            superAdmin.setMustChangePassword(false);
            return superAdmin;
        });
    }

    protected User reload(User user) {
        return userRepository.findById(user.getId()).orElseThrow();
    }

    /** A valid access token for the user's current state. */
    protected String tokenFor(User user) {
        return jwtService.generateAccessToken(reload(user)).value();
    }

    protected String serviceToken() {
        return jwtService.generateServiceToken("order-service").value();
    }

    // ---------------------------------------------------------------------------------------------------- HTTP

    protected static MockHttpServletRequestBuilder withBearer(MockHttpServletRequestBuilder request, String token) {
        return token == null ? request : request.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }

    protected static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder request, String body) {
        return request.contentType(MediaType.APPLICATION_JSON).content(body);
    }

    protected ResultActions login(String email, String password) throws Exception {
        return mockMvc.perform(json(post("/api/auth/login"),
                "{\"email\":\"%s\",\"password\":\"%s\"}".formatted(email, password)));
    }

    /** Signs in through the API and returns the response body. */
    protected String loginOk(String email, String password) throws Exception {
        return login(email, password).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    }

    protected static String read(String json, String path) {
        Object value = JsonPath.read(json, path);
        return value == null ? null : value.toString();
    }
}
