package com.achintha.userservice.security;

import com.achintha.userservice.config.AuthProperties;
import com.achintha.userservice.config.InternalAuthProperties;
import com.achintha.userservice.config.JwtProperties;
import com.achintha.userservice.user.AssistantPermission;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

/**
 * Issues RS256 access tokens (users) and service tokens ({@code ROLE_SERVICE}). The private key never leaves this
 * service; everyone else verifies with the public key from {@code /.well-known/jwks.json}.
 *
 * <p>User token claims are exactly those of section 3.3: {@code sub, pid, role, status, storeId, perms, tv, iss,
 * aud, iat, exp, jti}.
 */
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtProperties jwtProperties;
    private final AuthProperties authProperties;
    private final InternalAuthProperties internalProperties;
    private final Clock clock;

    public AccessToken generateAccessToken(User user) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(authProperties.accessTokenTtl());
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.issuer())
                .audience(List.of(jwtProperties.audience()))
                .subject(user.getId().toString())
                .issuedAt(now)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim(TokenClaims.PUBLIC_ID, user.getPublicId())
                .claim(TokenClaims.ROLE, user.getRole().name())
                // BAN_GRACE is never revealed to the merchant, not even inside the token
                .claim(TokenClaims.STATUS, user.visibleStatus().name())
                .claim(TokenClaims.TOKEN_VERSION, user.getTokenVersion());
        if (user.getStoreId() != null) {
            claims.claim(TokenClaims.STORE_ID, user.getStoreId().toString());
        }
        if (user.getRole() == Role.ROLE_ASSISTANT) {
            claims.claim(TokenClaims.PERMISSIONS,
                    user.effectivePermissions().stream().map(AssistantPermission::name).sorted().toList());
        }
        return new AccessToken(encode(claims.build()), now, expiresAt);
    }

    public AccessToken generateServiceToken(String clientId) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(Duration.ofMinutes(internalProperties.serviceTokenMinutes()));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.issuer())
                .audience(List.of(jwtProperties.audience()))
                .subject(clientId)
                .issuedAt(now)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim(TokenClaims.ROLE, Role.ROLE_SERVICE.name())
                .claim(TokenClaims.SERVICE, clientId)
                .build();
        return new AccessToken(encode(claims), now, expiresAt);
    }

    private String encode(JwtClaimsSet claims) {
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(jwtProperties.signing().keyId())
                .type("JWT")
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    public record AccessToken(String value, Instant issuedAt, Instant expiresAt) {

        public long expiresInSeconds() {
            return Duration.between(issuedAt, expiresAt).toSeconds();
        }

        @Override
        public String toString() {
            return "AccessToken[value=****, expiresAt=" + expiresAt + "]";
        }
    }
}
