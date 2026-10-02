package com.achintha.userservice.auth;

import com.achintha.userservice.config.AuthProperties;
import com.achintha.userservice.exception.ApiException;
import com.achintha.userservice.exception.ErrorCode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Opaque refresh tokens: random 256-bit values, stored hashed, rotated on every use with reuse detection. */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    public static final String REASON_REUSE = "REUSE_DETECTED";
    public static final String REASON_LOGOUT = "LOGOUT";

    private final SecureRandom random = new SecureRandom();
    private final RefreshTokenRepository repository;
    private final AuthProperties properties;
    private final Clock clock;

    /** Starts a new token family (a login). */
    @Transactional(propagation = Propagation.MANDATORY)
    public IssuedRefreshToken issueNewFamily(UUID userId) {
        return issue(userId, UUID.randomUUID(), null);
    }

    /**
     * Exchanges a refresh token for a new one of the same family. Reuse of an already-exchanged token revokes the
     * whole family; the caller's transaction must not roll back on the thrown {@link ApiException} so the revocation
     * sticks.
     */
    @Transactional(propagation = Propagation.MANDATORY, noRollbackFor = ApiException.class)
    public Rotation rotate(String rawToken) {
        Instant now = clock.instant();
        RefreshToken token = repository.findForUpdate(hash(rawToken))
                .orElseThrow(RefreshTokenService::invalid);
        if (token.getRevokedAt() != null) {
            throw invalid();
        }
        if (token.getUsedAt() != null) {
            repository.revokeFamily(token.getFamilyId(), now, REASON_REUSE);
            throw ApiException.unauthorized(ErrorCode.REFRESH_TOKEN_REUSED,
                    "Refresh token reuse detected; all sessions of this login were signed out");
        }
        if (!token.getExpiresAt().isAfter(now)) {
            throw invalid();
        }
        token.setUsedAt(now);
        return new Rotation(token.getUserId(), token.getFamilyId(),
                issue(token.getUserId(), token.getFamilyId(), token.getId()));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void revokeFamily(UUID familyId, String reason) {
        repository.revokeFamily(familyId, clock.instant(), reason);
    }

    /** Logout: revokes the presented token's family if it belongs to the caller; unknown tokens are ignored. */
    @Transactional
    public void revokeFamilyOf(String rawToken, UUID userId) {
        repository.findByTokenHash(hash(rawToken))
                .filter(token -> token.getUserId().equals(userId))
                .ifPresent(token -> repository.revokeFamily(token.getFamilyId(), clock.instant(), REASON_LOGOUT));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void revokeAllForUser(UUID userId, String reason) {
        repository.revokeAllForUser(userId, clock.instant(), reason);
    }

    private IssuedRefreshToken issue(UUID userId, UUID familyId, UUID rotatedFrom) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Instant now = clock.instant();
        RefreshToken token = new RefreshToken();
        token.setId(UUID.randomUUID());
        token.setUserId(userId);
        token.setTokenHash(hash(raw));
        token.setFamilyId(familyId);
        token.setRotatedFrom(rotatedFrom);
        token.setIssuedAt(now);
        token.setExpiresAt(now.plus(properties.refreshTokenTtl()));
        repository.save(token);
        return new IssuedRefreshToken(raw, token.getExpiresAt());
    }

    static String hash(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static ApiException invalid() {
        return ApiException.unauthorized(ErrorCode.INVALID_REFRESH_TOKEN, "Invalid or expired refresh token");
    }

    public record IssuedRefreshToken(String value, Instant expiresAt) {

        @Override
        public String toString() {
            return "IssuedRefreshToken[value=****, expiresAt=" + expiresAt + "]";
        }
    }

    public record Rotation(UUID userId, UUID familyId, IssuedRefreshToken next) {
    }
}
