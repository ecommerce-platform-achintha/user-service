package com.achintha.userservice.security;

import com.achintha.userservice.config.JwtProperties;
import com.achintha.userservice.config.SecurityConfig;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

/** Issues signed HS256 access tokens. Validation is done by the resource-server JwtDecoder. */
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtProperties properties;
    private final Clock clock;

    public AccessToken generateAccessToken(User user) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(properties.accessTokenTtl());
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.issuer())
                .subject(user.getId().toString())
                .issuedAt(now)
                .expiresAt(expiresAt)
                .claim("email", user.getEmail())
                .claim(SecurityConfig.ROLES_CLAIM, user.getRoles().stream().map(Role::name).sorted().toList())
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new AccessToken(token, now, expiresAt);
    }

    public record AccessToken(String value, Instant issuedAt, Instant expiresAt) {

        public long expiresInSeconds() {
            return Duration.between(issuedAt, expiresAt).toSeconds();
        }
    }
}
