package com.achintha.userservice.internal;

import com.achintha.userservice.auth.AuthRequests.ServiceTokenRequest;
import com.achintha.userservice.auth.AuthRequests.ServiceTokenResponse;
import com.achintha.userservice.auth.ServiceTokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Service-to-service token endpoint. {@code /internal/**} is never routed by the api-gateway and is excluded from
 * the public OpenAPI document.
 */
@RestController
@RequiredArgsConstructor
public class ServiceTokenController {

    private final ServiceTokenService serviceTokenService;

    @PostMapping("/internal/auth/service-token")
    public ResponseEntity<ServiceTokenResponse> serviceToken(@Valid @RequestBody ServiceTokenRequest request) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(serviceTokenService.issue(request.clientId(), request.clientSecret()));
    }
}
