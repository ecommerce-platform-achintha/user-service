package com.achintha.userservice.config;

import jakarta.validation.constraints.Positive;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Token lifetimes and login throttling (section 3.3; platform setting keys {@code auth.*}, section 7). */
@Validated
@ConfigurationProperties("auth")
public record AuthProperties(
        @Positive int accessTokenMinutes,
        @Positive int refreshDays,
        @Positive int maxFailedLogins,
        @Positive int lockoutMinutes,
        @Positive int ipMaxFailedLogins,
        boolean trustForwardedFor) {

    public Duration accessTokenTtl() {
        return Duration.ofMinutes(accessTokenMinutes);
    }

    public Duration refreshTokenTtl() {
        return Duration.ofDays(refreshDays);
    }

    public Duration lockoutDuration() {
        return Duration.ofMinutes(lockoutMinutes);
    }
}
