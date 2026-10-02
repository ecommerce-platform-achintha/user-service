package com.achintha.userservice.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Access-token settings (section 3.3). The signing keys have no default on purpose: they come from the Config Server
 * or the JWT_PRIVATE_KEY / JWT_PUBLIC_KEY environment variables, and startup fails without them.
 */
@Validated
@ConfigurationProperties("security.jwt")
public record JwtProperties(
        @NotBlank String issuer,
        @NotBlank String audience,
        @PositiveOrZero long clockSkewSeconds,
        @NotNull @Valid Signing signing) {

    /**
     * @param privateKey PKCS#8 PEM text ("-----BEGIN PRIVATE KEY-----") or a resource location
     *                   ({@code file:./keys/jwt-private.pem})
     * @param publicKey  X.509 PEM text ("-----BEGIN PUBLIC KEY-----") or a resource location
     * @param keyId      the {@code kid} header and JWKS entry id
     */
    public record Signing(
            @NotBlank(message = "is required (JWT_PRIVATE_KEY): PEM text or a resource location") String privateKey,
            @NotBlank(message = "is required (JWT_PUBLIC_KEY): PEM text or a resource location") String publicKey,
            @NotBlank String keyId) {

        @Override
        public String toString() {
            return "Signing[privateKey=****, publicKey=" + publicKey + ", keyId=" + keyId + "]";
        }
    }
}
