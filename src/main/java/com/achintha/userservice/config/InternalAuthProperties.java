package com.achintha.userservice.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Clients allowed to obtain {@code ROLE_SERVICE} tokens from {@code POST /internal/auth/service-token}. Secrets come
 * from the Config Server ({@code SERVICE_CLIENT_SECRET_<NAME>}); see {@link InternalClientSecretGuard}.
 */
@Validated
@ConfigurationProperties("security.internal")
public record InternalAuthProperties(
        @Positive int serviceTokenMinutes,
        @Valid List<Client> clients) {

    public InternalAuthProperties {
        clients = clients == null ? List.of() : List.copyOf(clients);
    }

    public record Client(@NotBlank String clientId, @NotBlank String clientSecret) {

        @Override
        public String toString() {
            return "Client[clientId=" + clientId + ", clientSecret=****]";
        }
    }
}
