package com.achintha.userservice.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.achintha.userservice.config.JwtProperties;
import com.achintha.userservice.config.SecurityConfig;
import com.achintha.userservice.security.JwtService.AccessToken;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

class JwtServiceTest {

    private static final String SECRET = "test-secret-that-is-at-least-32-bytes-long!!";
    private static final Duration TTL = Duration.ofMinutes(15);

    private final SecurityConfig securityConfig = new SecurityConfig();
    private final JwtProperties properties = new JwtProperties(SECRET, "user-service", TTL);

    private JwtDecoder decoder;
    private User user;

    @BeforeEach
    void setUp() {
        decoder = decoderFor(properties);
        user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("jane@example.com");
        user.setRoles(Set.of(Role.ROLE_CUSTOMER, Role.ROLE_ADMIN));
    }

    @Test
    void generatedTokenValidatesAndCarriesClaims() {
        Instant before = Instant.now();
        AccessToken token = serviceWith(properties, Clock.systemUTC()).generateAccessToken(user);

        Jwt jwt = decoder.decode(token.value());

        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getClaimAsString("email")).isEqualTo("jane@example.com");
        assertThat(jwt.getClaimAsStringList(SecurityConfig.ROLES_CLAIM))
                .containsExactlyInAnyOrder("ROLE_CUSTOMER", "ROLE_ADMIN");
        assertThat(jwt.getClaimAsString("iss")).isEqualTo("user-service");
        assertThat(jwt.getHeaders()).containsEntry("alg", "HS256");
        assertThat(Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt())).isEqualTo(TTL);
        assertThat(jwt.getIssuedAt()).isAfterOrEqualTo(before.minusSeconds(1));
        assertThat(token.expiresInSeconds()).isEqualTo(TTL.toSeconds());
    }

    @Test
    void rejectsExpiredToken() {
        // Issued long enough ago that it is past expiry plus the default 60s clock skew
        Clock past = Clock.fixed(Instant.now().minus(TTL).minusSeconds(120), ZoneOffset.UTC);
        String token = serviceWith(properties, past).generateAccessToken(user).value();

        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void rejectsTamperedToken() {
        String token = serviceWith(properties, Clock.systemUTC()).generateAccessToken(user).value();
        String[] parts = token.split("\\.");
        char last = parts[2].charAt(0);
        String tampered = parts[0] + "." + parts[1] + "." + (last == 'A' ? 'B' : 'A') + parts[2].substring(1);

        assertThatThrownBy(() -> decoder.decode(tampered)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsTokenSignedWithDifferentSecret() {
        JwtProperties other = new JwtProperties("another-secret-that-is-also-32-bytes-long!", "user-service", TTL);
        String token = serviceWith(other, Clock.systemUTC()).generateAccessToken(user).value();

        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsTokenFromDifferentIssuer() {
        JwtProperties otherIssuer = new JwtProperties(SECRET, "someone-else", TTL);
        String token = serviceWith(otherIssuer, Clock.systemUTC()).generateAccessToken(user).value();

        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsGarbage() {
        assertThatThrownBy(() -> decoder.decode("not-a-jwt")).isInstanceOf(JwtException.class);
    }

    private JwtService serviceWith(JwtProperties props, Clock clock) {
        SecretKey key = securityConfig.jwtSigningKey(props);
        return new JwtService(securityConfig.jwtEncoder(key), props, clock);
    }

    private JwtDecoder decoderFor(JwtProperties props) {
        return securityConfig.jwtDecoder(securityConfig.jwtSigningKey(props), props);
    }
}
