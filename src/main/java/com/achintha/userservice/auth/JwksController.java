package com.achintha.userservice.auth;

import com.nimbusds.jose.jwk.JWKSet;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Duration;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Public verification keys (RFC 7517). Only the public half of the key pair is ever serialized here. */
@RestController
@Tag(name = "Authentication")
public class JwksController {

    private final Map<String, Object> jwks;

    public JwksController(JWKSet publicJwkSet) {
        // toJSONObject() exports public parameters only (publicKeysOnly = true)
        this.jwks = publicJwkSet.toPublicJWKSet().toJSONObject(true);
    }

    @GetMapping("/.well-known/jwks.json")
    @Operation(summary = "JSON Web Key Set used to verify access tokens (RS256)")
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
                .body(jwks);
    }
}
