package com.achintha.userservice.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Registry of the service clients (the secrets themselves stay in the Config Server / secret store). A client can be
 * disabled here ({@code enabled=false}) without a redeploy.
 */
@Entity
@Table(name = "service_clients")
@Getter
@Setter
@NoArgsConstructor
public class ServiceClient {

    @Id
    @Column(name = "client_id", length = 64)
    private String clientId;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_token_issued_at")
    private Instant lastTokenIssuedAt;
}
