package com.achintha.userservice.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.achintha.userservice.UserServiceApplication;
import com.achintha.userservice.audit.AuditLogRepository;
import com.achintha.userservice.support.SharedPostgres;
import com.achintha.userservice.support.TestKeys;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserRepository;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Super-admin bootstrap (section 3.5), each case against its own fresh database in the shared PostgreSQL container
 * ({@link SharedPostgres}), so the database of the other integration tests is not touched.
 */
class SuperAdminBootstrapTest {

    private static final String EMAIL = "Root@Bootstrap.test";
    private static final String PASSWORD = "Bootstrap-Pass-2026!";

    @Test
    void createsExactlyOneSuperAdminAndIsIdempotent() throws Exception {
        try (ConfigurableApplicationContext context = start(freshDatabase(), EMAIL, PASSWORD)) {
            UserRepository users = context.getBean(UserRepository.class);
            List<User> superAdmins = users.findAll().stream()
                    .filter(u -> u.getRole() == Role.ROLE_SUPER_ADMIN).toList();
            assertThat(superAdmins).hasSize(1);
            User superAdmin = superAdmins.getFirst();
            assertThat(superAdmin.getEmail()).isEqualTo("root@bootstrap.test");
            assertThat(superAdmin.isMustChangePassword()).isTrue();
            assertThat(superAdmin.getPasswordHash()).startsWith("{argon2}").doesNotContain(PASSWORD);
            assertThat(context.getBean(AuditLogRepository.class).findAll())
                    .anySatisfy(entry -> assertThat(entry.getAction()).isEqualTo("SUPER_ADMIN_BOOTSTRAPPED"));

            // Running again (another replica, a restart), even concurrently, changes nothing
            SuperAdminBootstrap bootstrap = context.getBean(SuperAdminBootstrap.class);
            ApplicationArguments args = new DefaultApplicationArguments();
            ExecutorService pool = Executors.newFixedThreadPool(3);
            try {
                List<Future<Object>> runs = pool.invokeAll(List.<Callable<Object>>of(
                        () -> { bootstrap.run(args); return null; },
                        () -> { bootstrap.run(args); return null; },
                        () -> { bootstrap.run(args); return null; }));
                for (Future<Object> run : runs) {
                    run.get();
                }
            } finally {
                pool.shutdownNow();
            }
            assertThat(users.findAll().stream().filter(u -> u.getRole() == Role.ROLE_SUPER_ADMIN)).hasSize(1);
        }
    }

    @Test
    void failsStartupOnAnEmptyDatabaseWithoutTheValues() throws Exception {
        String url = freshDatabase();
        assertThatThrownBy(() -> start(url, "", "").close())
                .hasStackTraceContaining("SUPER_ADMIN_EMAIL and SUPER_ADMIN_INITIAL_PASSWORD");
        assertThatThrownBy(() -> start(url, EMAIL, "").close())
                .hasStackTraceContaining("SUPER_ADMIN_EMAIL and SUPER_ADMIN_INITIAL_PASSWORD");
    }

    @Test
    void rejectsAWeakInitialPassword() throws Exception {
        String url = freshDatabase();
        assertThatThrownBy(() -> start(url, EMAIL, "short").close())
                .hasStackTraceContaining("SUPER_ADMIN_INITIAL_PASSWORD must be at least 12 characters");
    }

    /** Command-line arguments, so they win over application.yml. */
    private static ConfigurableApplicationContext start(String jdbcUrl, String email, String password) {
        return new SpringApplicationBuilder(UserServiceApplication.class).run(
                "--server.port=0",
                "--spring.cloud.config.enabled=false",
                "--eureka.client.enabled=false",
                "--app.scheduling.enabled=false",
                "--spring.datasource.url=" + jdbcUrl,
                "--spring.datasource.username=" + IntegrationTestDatabase.username(),
                "--spring.datasource.password=" + IntegrationTestDatabase.password(),
                "--security.jwt.signing.private-key=" + TestKeys.PRIVATE_PEM,
                "--security.jwt.signing.public-key=" + TestKeys.PUBLIC_PEM,
                "--bootstrap.super-admin.email=" + email,
                "--bootstrap.super-admin.initial-password=" + password);
    }

    /** Creates an empty database in the shared container and returns its JDBC URL. */
    private static String freshDatabase() throws Exception {
        String name = "bootstrap_" + UUID.randomUUID().toString().replace("-", "");
        try (Connection connection = DriverManager.getConnection(IntegrationTestDatabase.jdbcUrl(),
                IntegrationTestDatabase.username(), IntegrationTestDatabase.password());
             Statement statement = connection.createStatement()) {
            statement.execute("create database " + name);
        }
        return IntegrationTestDatabase.jdbcUrl().replaceFirst("/[^/?]+(\\?|$)", "/" + name + "$1");
    }

    private static final class IntegrationTestDatabase {

        static String jdbcUrl() {
            return SharedPostgres.CONTAINER.getJdbcUrl();
        }

        static String username() {
            return SharedPostgres.CONTAINER.getUsername();
        }

        static String password() {
            return SharedPostgres.CONTAINER.getPassword();
        }
    }
}
