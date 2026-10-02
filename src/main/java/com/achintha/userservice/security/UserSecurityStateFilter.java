package com.achintha.userservice.security;

import com.achintha.userservice.exception.ApiException;
import com.achintha.userservice.exception.ErrorCode;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.SecuritySnapshot;
import com.achintha.userservice.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Runs after the bearer-token filter. user-service is the source of truth for security state, so it checks every
 * user token against the database (one primary-key lookup):
 * <ul>
 *   <li>{@code tv} older than the user's token version (ban, unban, permission/role change, removal, password
 *       change), or the user no longer exists: 401 {@code TOKEN_REVOKED};</li>
 *   <li>{@code mustChangePassword}: 403 {@code PASSWORD_CHANGE_REQUIRED} on every endpoint except change-password
 *       and logout.</li>
 * </ul>
 * Service tokens ({@code ROLE_SERVICE}) carry no user state and are not checked here.
 *
 * <p>Not a Spring bean on purpose: it is added to the security chain only (a bean would also be registered as a
 * servlet filter and run twice).
 */
public class UserSecurityStateFilter extends OncePerRequestFilter {

    static final Set<String> ALLOWED_WHILE_PASSWORD_CHANGE_REQUIRED =
            Set.of("/api/auth/change-password", "/api/auth/logout");

    private final UserRepository userRepository;
    private final HandlerExceptionResolver resolver;

    public UserSecurityStateFilter(UserRepository userRepository, HandlerExceptionResolver resolver) {
        this.userRepository = userRepository;
        this.resolver = resolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwtAuth && isUserToken(jwtAuth.getToken())) {
            ApiException rejection = check(jwtAuth.getToken(), request);
            if (rejection != null) {
                SecurityContextHolder.clearContext();
                if (rejection.code() == ErrorCode.TOKEN_REVOKED) {
                    response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
                }
                resolver.resolveException(request, response, null, rejection);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private static boolean isUserToken(Jwt jwt) {
        return !Role.ROLE_SERVICE.name().equals(jwt.getClaimAsString(TokenClaims.ROLE));
    }

    private ApiException check(Jwt jwt, HttpServletRequest request) {
        Optional<SecuritySnapshot> snapshot;
        Object tv = jwt.getClaim(TokenClaims.TOKEN_VERSION);
        try {
            snapshot = userRepository.findSecuritySnapshot(UUID.fromString(jwt.getSubject()));
        } catch (IllegalArgumentException e) {
            snapshot = Optional.empty();
        }
        if (snapshot.isEmpty() || !(tv instanceof Number version)
                || version.longValue() != snapshot.get().tokenVersion()) {
            return ApiException.unauthorized(ErrorCode.TOKEN_REVOKED,
                    "This token has been revoked; sign in again");
        }
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if (snapshot.get().mustChangePassword() && !ALLOWED_WHILE_PASSWORD_CHANGE_REQUIRED.contains(path)) {
            return ApiException.forbidden(ErrorCode.PASSWORD_CHANGE_REQUIRED,
                    "You must change your password before continuing (POST /api/auth/change-password)");
        }
        return null;
    }
}
