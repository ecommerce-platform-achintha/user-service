package com.achintha.userservice.auth;

import com.achintha.userservice.config.AuthProperties;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Failed-login counting and lockout (section 3.3: lock for {@code auth.lockout-minutes} after
 * {@code auth.max-failed-logins} failures).
 * <ul>
 *   <li>known accounts: {@code users.failed_login_count / locked_until};</li>
 *   <li>unknown emails: a {@code login_throttle} row per email, so a locked response does not reveal whether the
 *       account exists;</li>
 *   <li>client IPs: a {@code login_throttle} row per IP ({@code auth.ip-max-failed-logins}).</li>
 * </ul>
 * Every method commits on its own ({@code REQUIRES_NEW}): a failed login throws, and the count must survive that.
 */
@Service
@RequiredArgsConstructor
public class LoginThrottleService {

    private final JdbcTemplate jdbcTemplate;
    private final AuthProperties properties;
    private final Clock clock;

    public static String ipKey(String ip) {
        return "ip:" + ip;
    }

    public static String emailKey(String normalizedEmail) {
        return "email:" + normalizedEmail.toLowerCase(Locale.ROOT);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, readOnly = true)
    public boolean isLocked(String key) {
        List<Timestamp> lockedUntil = jdbcTemplate.queryForList(
                "select locked_until from login_throttle where throttle_key = ?", Timestamp.class, key);
        return !lockedUntil.isEmpty() && lockedUntil.getFirst() != null
                && lockedUntil.getFirst().toInstant().isAfter(clock.instant());
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(String key, int maxFailures) {
        Instant now = clock.instant();
        Timestamp nowTs = Timestamp.from(now);
        // A failure window lasts lockout-minutes; older failures are forgotten
        Timestamp windowStart = Timestamp.from(now.minus(properties.lockoutDuration()));
        Integer count = jdbcTemplate.queryForObject("""
                insert into login_throttle (throttle_key, failed_count, window_started_at, locked_until, updated_at)
                values (?, 1, ?, null, ?)
                on conflict (throttle_key) do update set
                    failed_count = case when login_throttle.window_started_at < ? then 1
                                        else login_throttle.failed_count + 1 end,
                    window_started_at = case when login_throttle.window_started_at < ? then excluded.window_started_at
                                             else login_throttle.window_started_at end,
                    updated_at = excluded.updated_at
                returning failed_count
                """, Integer.class, key, nowTs, nowTs, windowStart, windowStart);
        if (count != null && count >= maxFailures) {
            jdbcTemplate.update("""
                    update login_throttle set failed_count = 0, window_started_at = ?, locked_until = ?
                    where throttle_key = ?
                    """, nowTs, Timestamp.from(now.plus(properties.lockoutDuration())), key);
        }
    }

    /** Counts a wrong password on a known account and locks it at the threshold. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordUserFailure(UUID userId) {
        Integer count = jdbcTemplate.queryForObject(
                "update users set failed_login_count = failed_login_count + 1 where id = ? returning failed_login_count",
                Integer.class, userId);
        if (count != null && count >= properties.maxFailedLogins()) {
            jdbcTemplate.update("update users set failed_login_count = 0, locked_until = ? where id = ?",
                    Timestamp.from(clock.instant().plus(properties.lockoutDuration())), userId);
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void resetUser(UUID userId) {
        jdbcTemplate.update("""
                update users set failed_login_count = 0, locked_until = null
                where id = ? and (failed_login_count <> 0 or locked_until is not null)
                """, userId);
    }
}
