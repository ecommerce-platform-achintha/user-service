package com.achintha.userservice.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * JWT settings. {@code secret} has no default on purpose: it must come from the
 * Config Server (or the SECURITY_JWT_SECRET env var), and startup fails without it.
 */
@Validated
@ConfigurationProperties("security.jwt")
public record JwtProperties(
        // HS256 requires a key of at least 256 bits
        @NotBlank @Size(min = 32, message = "must be at least 32 characters (256 bits) for HS256") String secret,
        @NotBlank String issuer,
        @NotNull Duration accessTokenTtl) {
}
