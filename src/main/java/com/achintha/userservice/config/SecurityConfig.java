package com.achintha.userservice.config;

import com.achintha.userservice.security.DelegatingAuthErrorHandler;
import com.achintha.userservice.security.TokenClaims;
import com.achintha.userservice.security.UserSecurityStateFilter;
import com.achintha.userservice.user.AssistantPermission;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Deny-by-default security (sections 3.4 and 11). Path prefixes are enforced here and again with
 * {@code @PreAuthorize} on every controller method.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private static final String[] PUBLIC_DOCS = {"/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**"};

    private static final String CUSTOMER = Role.ROLE_CUSTOMER.name();
    private static final String MERCHANT = Role.ROLE_MERCHANT.name();
    private static final String ASSISTANT = Role.ROLE_ASSISTANT.name();
    private static final String ADMIN = Role.ROLE_ADMIN.name();
    private static final String SUPER_ADMIN = Role.ROLE_SUPER_ADMIN.name();
    private static final String SERVICE = Role.ROLE_SERVICE.name();
    private static final String[] USER_ROLES = {CUSTOMER, MERCHANT, ASSISTANT, ADMIN, SUPER_ADMIN};

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, DelegatingAuthErrorHandler authErrorHandler,
                                            UserRepository userRepository,
                                            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver)
            throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable) // CORS is answered by the api-gateway only
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // Public
                        .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/refresh").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/users/register/customer",
                                "/api/users/register/merchant").permitAll()
                        .requestMatchers(HttpMethod.POST, "/internal/auth/service-token").permitAll()
                        .requestMatchers(PUBLIC_DOCS).permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll()
                        .requestMatchers("/error").permitAll()
                        // Authenticated, by prefix (section 3.4)
                        .requestMatchers(HttpMethod.POST, "/api/auth/logout", "/api/auth/change-password")
                        .hasAnyAuthority(USER_ROLES)
                        .requestMatchers("/internal/**").hasAuthority(SERVICE)
                        .requestMatchers("/api/super-admin/**").hasAuthority(SUPER_ADMIN)
                        .requestMatchers("/api/admin/**").hasAnyAuthority(ADMIN, SUPER_ADMIN)
                        .requestMatchers("/api/merchant/owner/**").hasAuthority(MERCHANT)
                        .requestMatchers("/api/merchant/**").hasAnyAuthority(MERCHANT, ASSISTANT)
                        .requestMatchers("/api/customer/**").hasAuthority(CUSTOMER)
                        .requestMatchers("/api/users/**").hasAnyAuthority(USER_ROLES)
                        .anyRequest().denyAll())
                // BearerTokenAuthenticationFilter: validates the JWT and populates the SecurityContext
                .oauth2ResourceServer(rs -> rs
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                        .authenticationEntryPoint(authErrorHandler)
                        .accessDeniedHandler(authErrorHandler))
                .addFilterAfter(new UserSecurityStateFilter(userRepository, resolver),
                        BearerTokenAuthenticationFilter.class)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authErrorHandler)
                        .accessDeniedHandler(authErrorHandler));
        return http.build();
    }

    /** Argon2id for new hashes; bcrypt hashes still verify (and are upgraded on the next successful login). */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return SecurityConfig.createPasswordEncoder();
    }

    public static PasswordEncoder createPasswordEncoder() {
        String defaultId = "argon2";
        DelegatingPasswordEncoder encoder = new DelegatingPasswordEncoder(defaultId, Map.of(
                defaultId, Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(),
                "bcrypt", new BCryptPasswordEncoder()));
        // Hashes without an {id} prefix are treated as bcrypt
        encoder.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder());
        return encoder;
    }

    @Bean
    RsaKeyLoader.KeyPair jwtKeyPair(JwtProperties properties, ResourceLoader resourceLoader) {
        return RsaKeyLoader.load(properties.signing(), resourceLoader);
    }

    /** The public half only, as served at {@code /.well-known/jwks.json}. */
    @Bean
    public JWKSet publicJwkSet(RsaKeyLoader.KeyPair keyPair, JwtProperties properties) {
        RSAKey key = new RSAKey.Builder(keyPair.publicKey())
                .keyID(properties.signing().keyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        return new JWKSet(key);
    }

    @Bean
    public JwtEncoder jwtEncoder(RsaKeyLoader.KeyPair keyPair, JwtProperties properties) {
        return NimbusJwtEncoder.withKeyPair(keyPair.publicKey(), keyPair.privateKey())
                .algorithm(SignatureAlgorithm.RS256)
                .jwkPostProcessor(jwk -> jwk.keyID(properties.signing().keyId()))
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(RsaKeyLoader.KeyPair keyPair, JwtProperties properties, Clock clock) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(keyPair.publicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(tokenValidator(properties, clock));
        return decoder;
    }

    /** exp/nbf with the configured skew, issuer, audience, and a non-blank subject and role. */
    static OAuth2TokenValidator<Jwt> tokenValidator(JwtProperties properties, Clock clock) {
        JwtTimestampValidator timestamps = new JwtTimestampValidator(
                Duration.ofSeconds(properties.clockSkewSeconds()));
        timestamps.setClock(clock);
        List<OAuth2TokenValidator<Jwt>> validators = List.of(
                timestamps,
                new JwtIssuerValidator(properties.issuer()),
                new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                        aud -> aud != null && aud.contains(properties.audience())),
                new JwtClaimValidator<String>(JwtClaimNames.SUB, sub -> sub != null && !sub.isBlank()),
                new JwtClaimValidator<String>(TokenClaims.ROLE, SecurityConfig::isKnownRole));
        return new DelegatingOAuth2TokenValidator<>(validators);
    }

    private static boolean isKnownRole(String role) {
        try {
            Role.valueOf(role);
            return true;
        } catch (IllegalArgumentException | NullPointerException e) {
            return false;
        }
    }

    /**
     * Authorities: the {@code role} claim, plus {@code PERM_*} for assistant permissions ({@code perms} claim). A
     * merchant implicitly holds every permission.
     */
    static JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(SecurityConfig::authorities);
        return converter;
    }

    private static Collection<GrantedAuthority> authorities(Jwt jwt) {
        String role = jwt.getClaimAsString(TokenClaims.ROLE);
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(role));
        if (MERCHANT.equals(role)) {
            for (AssistantPermission permission : AssistantPermission.values()) {
                authorities.add(new SimpleGrantedAuthority(permission.authority()));
            }
        } else if (ASSISTANT.equals(role)) {
            List<String> perms = jwt.getClaimAsStringList(TokenClaims.PERMISSIONS);
            if (perms != null) {
                perms.forEach(p -> authorities.add(new SimpleGrantedAuthority("PERM_" + p)));
            }
        }
        return authorities;
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
