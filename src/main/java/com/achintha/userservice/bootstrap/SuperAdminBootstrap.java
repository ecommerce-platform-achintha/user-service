package com.achintha.userservice.bootstrap;

import com.achintha.userservice.audit.AuditService;
import com.achintha.userservice.common.PasswordPolicy;
import com.achintha.userservice.config.SuperAdminBootstrapProperties;
import com.achintha.userservice.outbox.UserEventPublisher;
import com.achintha.userservice.security.Actor;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserAccountFactory;
import com.achintha.userservice.user.UserRepository;
import com.achintha.userservice.user.UserStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Creates the unique super admin on startup if there is none (section 3.5).
 * <ul>
 *   <li>Idempotent and safe across replicas: runs under a transaction-scoped PostgreSQL advisory lock, and the
 *       partial unique index {@code ux_users_single_super_admin} is the final guard.</li>
 *   <li>Email and initial password come from {@code SUPER_ADMIN_EMAIL} / {@code SUPER_ADMIN_INITIAL_PASSWORD}. On an
 *       empty database without them, startup fails. The password is never logged.</li>
 *   <li>The account has {@code mustChangePassword=true}; its creation is audit-logged.</li>
 * </ul>
 */
@Slf4j
@Component
@Order(0)
public class SuperAdminBootstrap implements ApplicationRunner {

    /** Arbitrary, stable key for {@code pg_advisory_xact_lock}. */
    static final long ADVISORY_LOCK_KEY = 0x5553525F5341L; // "USR_SA"

    private final UserRepository userRepository;
    private final UserAccountFactory accountFactory;
    private final UserEventPublisher events;
    private final AuditService audit;
    private final SuperAdminBootstrapProperties properties;
    private final TransactionTemplate transactionTemplate;
    private final JdbcTemplate jdbcTemplate;

    public SuperAdminBootstrap(UserRepository userRepository, UserAccountFactory accountFactory,
                               UserEventPublisher events, AuditService audit,
                               SuperAdminBootstrapProperties properties, TransactionTemplate transactionTemplate,
                               JdbcTemplate jdbcTemplate) {
        this.userRepository = userRepository;
        this.accountFactory = accountFactory;
        this.events = events;
        this.audit = audit;
        this.properties = properties;
        this.transactionTemplate = transactionTemplate;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(ApplicationArguments args) {
        transactionTemplate.executeWithoutResult(status -> {
            jdbcTemplate.queryForObject("select pg_advisory_xact_lock(?)::text", String.class, ADVISORY_LOCK_KEY);
            createIfMissing();
        });
    }

    private void createIfMissing() {
        if (userRepository.existsByRole(Role.ROLE_SUPER_ADMIN)) {
            log.debug("Super admin present; bootstrap skipped");
            return;
        }
        if (!properties.isComplete()) {
            if (userRepository.count() == 0) {
                throw new IllegalStateException("No super admin exists and the database is empty: set "
                        + "SUPER_ADMIN_EMAIL and SUPER_ADMIN_INITIAL_PASSWORD to bootstrap one");
            }
            log.warn("No super admin exists and SUPER_ADMIN_EMAIL / SUPER_ADMIN_INITIAL_PASSWORD are not set; "
                    + "skipping bootstrap");
            return;
        }
        String violation = PasswordPolicy.check(properties.initialPassword());
        if (violation != null) {
            throw new IllegalStateException("SUPER_ADMIN_INITIAL_PASSWORD " + violation);
        }
        User superAdmin = accountFactory.newUser(Role.ROLE_SUPER_ADMIN, UserStatus.ACTIVE, properties.email(),
                properties.initialPassword(), "Super", "Admin", null, null, Actor.SYSTEM);
        superAdmin.setMustChangePassword(true);
        userRepository.saveAndFlush(superAdmin);
        events.userRegistered(superAdmin);
        audit.recordUserChange(Actor.system(), "SUPER_ADMIN_BOOTSTRAPPED", superAdmin, null, null);
        log.info("Super admin {} created (password change required at first sign-in)", superAdmin.getPublicId());
    }
}
