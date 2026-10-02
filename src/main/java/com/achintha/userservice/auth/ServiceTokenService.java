package com.achintha.userservice.auth;

import com.achintha.userservice.auth.AuthRequests.ServiceTokenResponse;
import com.achintha.userservice.config.InternalAuthProperties;
import com.achintha.userservice.exception.ApiException;
import com.achintha.userservice.exception.ErrorCode;
import com.achintha.userservice.security.JwtService;
import com.achintha.userservice.security.JwtService.AccessToken;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Client-credentials exchange for {@code ROLE_SERVICE} tokens ({@code POST /internal/auth/service-token}). Secrets
 * are compared in constant time and never logged.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ServiceTokenService {

    private final InternalAuthProperties properties;
    private final ServiceClientRepository repository;
    private final JwtService jwtService;
    private final Clock clock;

    /** Registers configured clients that are not in {@code service_clients} yet (enabled by default). */
    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void syncConfiguredClients() {
        for (InternalAuthProperties.Client client : properties.clients()) {
            if (!repository.existsById(client.clientId())) {
                ServiceClient row = new ServiceClient();
                row.setClientId(client.clientId());
                row.setEnabled(true);
                row.setCreatedAt(clock.instant());
                repository.save(row);
                log.info("Registered service client {}", client.clientId());
            }
        }
    }

    @Transactional
    public ServiceTokenResponse issue(String clientId, String clientSecret) {
        Optional<InternalAuthProperties.Client> configured = properties.clients().stream()
                .filter(client -> client.clientId().equals(clientId))
                .findFirst();
        // Compare against something even for unknown ids, so timing does not reveal valid client ids
        String expected = configured.map(InternalAuthProperties.Client::clientSecret).orElse("\u0000unknown");
        boolean secretMatches = MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                clientSecret.getBytes(StandardCharsets.UTF_8));
        ServiceClient registered = configured.isPresent() ? repository.findById(clientId).orElse(null) : null;
        if (!secretMatches || registered == null || !registered.isEnabled()) {
            log.warn("Rejected service-token request for client id {}", clientId);
            throw ApiException.unauthorized(ErrorCode.INVALID_CLIENT_CREDENTIALS, "Invalid client credentials");
        }
        registered.setLastTokenIssuedAt(clock.instant());
        AccessToken token = jwtService.generateServiceToken(clientId);
        return new ServiceTokenResponse(token.value(), "Bearer", token.expiresInSeconds(), token.expiresAt());
    }
}
