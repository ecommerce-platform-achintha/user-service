package com.achintha.userservice.auth;

import com.achintha.userservice.auth.AuthRequests.ChangePasswordRequest;
import com.achintha.userservice.auth.RefreshTokenService.IssuedRefreshToken;
import com.achintha.userservice.auth.RefreshTokenService.Rotation;
import com.achintha.userservice.config.AuthProperties;
import com.achintha.userservice.exception.ApiException;
import com.achintha.userservice.exception.ErrorCode;
import com.achintha.userservice.exception.NotFoundException;
import com.achintha.userservice.security.JwtService;
import com.achintha.userservice.security.JwtService.AccessToken;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserRepository;
import java.time.Clock;
import java.util.Locale;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Login, refresh, logout and password change (section 3.3).
 *
 * <p>Wrong email and wrong password produce the same 401 {@code INVALID_CREDENTIALS} message, and an unknown email
 * still costs one password-hash comparison so timing does not reveal which accounts exist. Status-based refusals
 * ({@link LoginPolicy}) are only reported after the password is verified.
 */
@Slf4j
@Service
public class AuthService {

    static final String INVALID_CREDENTIALS_MESSAGE = "Invalid email or password";
    static final String LOCKED_MESSAGE = "Too many failed sign-in attempts. Try again later";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final LoginThrottleService throttle;
    private final LoginPolicy loginPolicy;
    private final TokenRevocationService tokenRevocation;
    private final AuthProperties properties;
    private final TransactionTemplate transactionTemplate;
    private final Clock clock;
    /** Compared against for unknown emails, to keep response times uniform. */
    private final String dummyHash;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService,
                       RefreshTokenService refreshTokenService, LoginThrottleService throttle,
                       LoginPolicy loginPolicy, TokenRevocationService tokenRevocation, AuthProperties properties,
                       TransactionTemplate transactionTemplate, Clock clock) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.throttle = throttle;
        this.loginPolicy = loginPolicy;
        this.tokenRevocation = tokenRevocation;
        this.properties = properties;
        this.transactionTemplate = transactionTemplate;
        this.clock = clock;
        this.dummyHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    public TokenResponse login(String email, String password, String clientIp) {
        String ipKey = LoginThrottleService.ipKey(clientIp);
        if (throttle.isLocked(ipKey)) {
            throw locked();
        }
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        User user = userRepository.findByEmail(normalizedEmail).orElse(null);

        if (user == null) {
            String emailKey = LoginThrottleService.emailKey(normalizedEmail);
            if (throttle.isLocked(emailKey)) {
                throw locked();
            }
            passwordEncoder.matches(password, dummyHash);
            throttle.recordFailure(ipKey, properties.ipMaxFailedLogins());
            throttle.recordFailure(emailKey, properties.maxFailedLogins());
            throw invalidCredentials();
        }
        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(clock.instant())) {
            throw locked();
        }
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throttle.recordFailure(ipKey, properties.ipMaxFailedLogins());
            throttle.recordUserFailure(user.getId());
            throw invalidCredentials();
        }
        throttle.resetUser(user.getId());
        loginPolicy.check(user);

        UUID userId = user.getId();
        return transactionTemplate.execute(status -> {
            User current = userRepository.findById(userId).orElseThrow(AuthService::invalidCredentials);
            if (passwordEncoder.upgradeEncoding(current.getPasswordHash())) {
                current.setPasswordHash(passwordEncoder.encode(password));
            }
            return issueTokens(current, refreshTokenService.issueNewFamily(userId));
        });
    }

    /**
     * Rotates the refresh token. The same sign-in rules as login apply, so a user banned since the last login cannot
     * keep refreshing. Not rolled back on {@link ApiException}: reuse detection must revoke the family for good.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public TokenResponse refresh(String rawRefreshToken) {
        Rotation rotation = refreshTokenService.rotate(rawRefreshToken);
        User user = userRepository.findById(rotation.userId())
                .orElseThrow(() -> ApiException.unauthorized(ErrorCode.INVALID_REFRESH_TOKEN,
                        "Invalid or expired refresh token"));
        try {
            loginPolicy.check(user);
        } catch (ApiException refused) {
            refreshTokenService.revokeFamily(rotation.familyId(), "SIGN_IN_REFUSED");
            throw refused;
        }
        return issueTokens(user, rotation.next());
    }

    public void logout(UUID userId, String rawRefreshToken) {
        refreshTokenService.revokeFamilyOf(rawRefreshToken, userId);
    }

    /**
     * Changes the caller's password, clears {@code mustChangePassword}, revokes every existing token (new
     * {@code tv}, all refresh tokens) and returns a fresh token pair.
     */
    @Transactional
    public TokenResponse changePassword(UUID userId, ChangePasswordRequest request) {
        User user = userRepository.findById(userId).orElseThrow(() -> new NotFoundException("User not found"));
        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, ErrorCode.INVALID_CREDENTIALS,
                    "Current password is incorrect");
        }
        if (passwordEncoder.matches(request.newPassword(), user.getPasswordHash())) {
            throw ApiException.badRequest(ErrorCode.PASSWORD_REUSED,
                    "The new password must be different from the current one");
        }
        if (request.newPassword().equalsIgnoreCase(user.getEmail())) {
            throw ApiException.badRequest(ErrorCode.WEAK_PASSWORD, "The password must not be your email address");
        }
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setMustChangePassword(false);
        tokenRevocation.revokeAllTokens(user, "PASSWORD_CHANGED");
        log.info("Password changed for user {}", user.getPublicId());
        return issueTokens(user, refreshTokenService.issueNewFamily(user.getId()));
    }

    private TokenResponse issueTokens(User user, IssuedRefreshToken refreshToken) {
        AccessToken access = jwtService.generateAccessToken(user);
        return new TokenResponse(access.value(), "Bearer", access.expiresInSeconds(), access.expiresAt(),
                refreshToken.value(), refreshToken.expiresAt(), user.getPublicId(), user.getRole(),
                user.visibleStatus(), user.visibleStatusReason(), user.isMustChangePassword());
    }

    private static ApiException invalidCredentials() {
        return ApiException.unauthorized(ErrorCode.INVALID_CREDENTIALS, INVALID_CREDENTIALS_MESSAGE);
    }

    private static ApiException locked() {
        return new ApiException(HttpStatus.TOO_MANY_REQUESTS, ErrorCode.TOO_MANY_LOGIN_ATTEMPTS, LOCKED_MESSAGE);
    }
}
