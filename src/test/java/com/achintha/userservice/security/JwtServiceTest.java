package com.achintha.userservice.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.achintha.userservice.config.AuthProperties;
import com.achintha.userservice.config.InternalAuthProperties;
import com.achintha.userservice.config.JwtProperties;
import com.achintha.userservice.config.RsaKeyLoader;
import com.achintha.userservice.config.SecurityConfig;
import com.achintha.userservice.security.JwtService.AccessToken;
import com.achintha.userservice.support.TestKeys;
import com.achintha.userservice.user.AssistantPermission;
import com.achintha.userservice.user.AssistantStatus;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserStatus;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

class JwtServiceTest {

    private static final AuthProperties AUTH = new AuthProperties(10, 14, 5, 15, 20, false);
    private static final InternalAuthProperties INTERNAL = new InternalAuthProperties(5, List.of());

    private final SecurityConfig securityConfig = new SecurityConfig();
    private final JwtProperties properties = properties("user-service", "marketplace", TestKeys.KEY_PAIR);

    @Test
    void merchantTokenCarriesExactlyTheContractClaims() {
        User merchant = user(Role.ROLE_MERCHANT, UserStatus.ACTIVE);
        merchant.setStoreId(UUID.randomUUID());

        Jwt jwt = decoder().decode(service(properties, TestKeys.KEY_PAIR, Clock.systemUTC())
                .generateAccessToken(merchant).value());

        assertThat(jwt.getClaims().keySet()).containsExactlyInAnyOrder(
                "sub", "pid", "role", "status", "storeId", "tv", "iss", "aud", "iat", "exp", "jti");
        assertThat(jwt.getSubject()).isEqualTo(merchant.getId().toString());
        assertThat(jwt.getClaimAsString("pid")).isEqualTo("USR-2610-ABCDEF");
        assertThat(jwt.getClaimAsString("role")).isEqualTo("ROLE_MERCHANT");
        assertThat(jwt.getClaimAsString("storeId")).isEqualTo(merchant.getStoreId().toString());
        assertThat(((Number) jwt.getClaim("tv")).longValue()).isEqualTo(3L);
        assertThat(jwt.getAudience()).containsExactly("marketplace");
        assertThat(jwt.getHeaders()).containsEntry("alg", "RS256").containsEntry("kid", "test-kid");
        assertThat(Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt())).isEqualTo(Duration.ofMinutes(10));
    }

    @Test
    void assistantTokenCarriesPermissionsAndBanGraceIsHidden() {
        User assistant = user(Role.ROLE_ASSISTANT, UserStatus.ACTIVE);
        assistant.setStoreId(UUID.randomUUID());
        assistant.setAssistantStatus(AssistantStatus.ACTIVE);
        assistant.setPermissions(EnumSet.of(AssistantPermission.ORDER_VIEW, AssistantPermission.ORDER_SHIP));
        User graceMerchant = user(Role.ROLE_MERCHANT, UserStatus.BAN_GRACE);
        graceMerchant.setStoreId(UUID.randomUUID());
        JwtService service = service(properties, TestKeys.KEY_PAIR, Clock.systemUTC());

        Jwt assistantJwt = decoder().decode(service.generateAccessToken(assistant).value());
        Jwt merchantJwt = decoder().decode(service.generateAccessToken(graceMerchant).value());

        assertThat(assistantJwt.getClaimAsStringList("perms")).containsExactly("ORDER_SHIP", "ORDER_VIEW");
        assertThat(merchantJwt.getClaimAsString("status")).isEqualTo("ACTIVE");
        assertThat(merchantJwt.getClaims()).doesNotContainKey("perms");
    }

    @Test
    void serviceTokenHasServiceRoleAndSvcClaim() {
        AccessToken token = service(properties, TestKeys.KEY_PAIR, Clock.systemUTC())
                .generateServiceToken("order-service");
        Jwt jwt = decoder().decode(token.value());

        assertThat(jwt.getClaimAsString("role")).isEqualTo("ROLE_SERVICE");
        assertThat(jwt.getClaimAsString("svc")).isEqualTo("order-service");
        assertThat(jwt.getAudience()).containsExactly("marketplace");
        assertThat(token.expiresInSeconds()).isEqualTo(300);
    }

    @Test
    void rejectsExpiredToken() {
        // Past expiry plus the 30 s skew
        Clock past = Clock.fixed(Instant.now().minus(Duration.ofMinutes(11)), ZoneOffset.UTC);
        String token = service(properties, TestKeys.KEY_PAIR, past)
                .generateAccessToken(user(Role.ROLE_CUSTOMER, UserStatus.ACTIVE)).value();

        assertThatThrownBy(() -> decoder().decode(token)).isInstanceOf(JwtException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void rejectsTokenSignedWithAnotherKey() {
        KeyPair other = TestKeys.generate();
        String token = service(properties("user-service", "marketplace", other), other, Clock.systemUTC())
                .generateAccessToken(user(Role.ROLE_CUSTOMER, UserStatus.ACTIVE)).value();

        assertThatThrownBy(() -> decoder().decode(token)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsWrongIssuerOrAudience() {
        String wrongIssuer = service(properties("someone-else", "marketplace", TestKeys.KEY_PAIR),
                TestKeys.KEY_PAIR, Clock.systemUTC()).generateAccessToken(user(Role.ROLE_CUSTOMER, UserStatus.ACTIVE))
                .value();
        String wrongAudience = service(properties("user-service", "other-app", TestKeys.KEY_PAIR),
                TestKeys.KEY_PAIR, Clock.systemUTC()).generateAccessToken(user(Role.ROLE_CUSTOMER, UserStatus.ACTIVE))
                .value();

        assertThatThrownBy(() -> decoder().decode(wrongIssuer)).isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> decoder().decode(wrongAudience)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsHs256AndUnsignedTokens() {
        byte[] secret = "a-shared-secret-that-is-32-bytes-long!!".getBytes(StandardCharsets.UTF_8);
        String hs256 = NimbusJwtEncoder.withSecretKey(new SecretKeySpec(secret, "HmacSHA256")).build()
                .encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(),
                        JwtClaimsSet.builder().issuer("user-service").audience(List.of("marketplace"))
                                .subject(UUID.randomUUID().toString()).claim("role", "ROLE_ADMIN")
                                .expiresAt(Instant.now().plusSeconds(60)).build()))
                .getTokenValue();
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String unsigned = b64.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(("{\"sub\":\"x\",\"role\":\"ROLE_ADMIN\",\"iss\":\"user-service\","
                + "\"aud\":[\"marketplace\"]}").getBytes(StandardCharsets.UTF_8)) + ".";

        assertThatThrownBy(() -> decoder().decode(hs256)).isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> decoder().decode(unsigned)).isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> decoder().decode("not-a-jwt")).isInstanceOf(JwtException.class);
    }

    @Test
    void keyLoaderRejectsMismatchedPublicKey() {
        KeyPair other = TestKeys.generate();
        JwtProperties.Signing mismatched = new JwtProperties.Signing(TestKeys.PRIVATE_PEM,
                TestKeys.pem("PUBLIC KEY", other.getPublic().getEncoded()), "kid");

        assertThatThrownBy(() -> RsaKeyLoader.load(mismatched, new DefaultResourceLoader()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageNotContaining("BEGIN");
    }

    private JwtDecoder decoder() {
        return securityConfig.jwtDecoder(keys(TestKeys.KEY_PAIR), properties, Clock.systemUTC());
    }

    private JwtService service(JwtProperties props, KeyPair keyPair, Clock clock) {
        return new JwtService(securityConfig.jwtEncoder(keys(keyPair), props), props, AUTH, INTERNAL, clock);
    }

    private static RsaKeyLoader.KeyPair keys(KeyPair keyPair) {
        return new RsaKeyLoader.KeyPair((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
    }

    private static JwtProperties properties(String issuer, String audience, KeyPair keyPair) {
        return new JwtProperties(issuer, audience, 30, new JwtProperties.Signing(
                TestKeys.pem("PRIVATE KEY", keyPair.getPrivate().getEncoded()),
                TestKeys.pem("PUBLIC KEY", keyPair.getPublic().getEncoded()), "test-kid"));
    }

    private static User user(Role role, UserStatus status) {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setPublicId("USR-2610-ABCDEF");
        user.setEmail("jane@example.com");
        user.setRole(role);
        user.setStatus(status);
        user.setTokenVersion(3);
        user.setPermissions(Set.of());
        return user;
    }
}
