package com.achintha.userservice.auth;

import com.achintha.userservice.outbox.UserEventPublisher;
import com.achintha.userservice.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Invalidates a user's outstanding access tokens by incrementing {@code tokenVersion} (section 3.3) and emits
 * {@code UserSecurityChanged} so every other service drops its cached state. Optionally also revokes all refresh
 * tokens, for changes after which the user must not silently get a new access token (ban, removal, password change).
 */
@Service
@RequiredArgsConstructor
public class TokenRevocationService {

    private final RefreshTokenService refreshTokenService;
    private final UserEventPublisher events;

    @Transactional(propagation = Propagation.MANDATORY)
    public void revokeAccessTokens(User user, String change) {
        user.incrementTokenVersion();
        events.securityChanged(user, change);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void revokeAllTokens(User user, String change) {
        revokeAccessTokens(user, change);
        refreshTokenService.revokeAllForUser(user.getId(), change);
    }
}
