package com.achintha.userservice.security;

import com.achintha.userservice.user.Role;
import java.util.UUID;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * The authenticated caller, derived only from the validated JWT (never from request bodies or headers).
 *
 * @param storeId merchant/assistant store from the token; used to scope every merchant-side query (BOLA)
 */
public record Actor(UUID id, String publicId, Role role, UUID storeId) {

    /** Actor id used for scheduler/bootstrap actions in audit rows and {@code statusChangedBy}. */
    public static final String SYSTEM = "SYSTEM";

    public static Actor from(Jwt jwt) {
        String storeId = jwt.getClaimAsString(TokenClaims.STORE_ID);
        return new Actor(
                UUID.fromString(jwt.getSubject()),
                jwt.getClaimAsString(TokenClaims.PUBLIC_ID),
                Role.valueOf(jwt.getClaimAsString(TokenClaims.ROLE)),
                storeId == null ? null : UUID.fromString(storeId));
    }

    public static Actor system() {
        return new Actor(null, SYSTEM, Role.ROLE_SERVICE, null);
    }
}
