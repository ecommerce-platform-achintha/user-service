package com.achintha.userservice.auth;

import com.achintha.userservice.auth.AuthRequests.ChangePasswordRequest;
import com.achintha.userservice.auth.AuthRequests.LogoutRequest;
import com.achintha.userservice.auth.AuthRequests.RefreshRequest;
import com.achintha.userservice.config.OpenApiConfig;
import com.achintha.userservice.security.Actor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication")
public class AuthController {

    private final AuthService authService;
    private final ClientIpResolver clientIpResolver;

    @PostMapping("/login")
    @Operation(summary = "Sign in", description = "Returns an access token (RS256, 10 min) and a refresh token. "
            + "401 INVALID_CREDENTIALS for any wrong email/password, 429 TOO_MANY_LOGIN_ATTEMPTS when locked, "
            + "403 for banned admins, banned/removed assistants and assistants of a banned merchant.")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request,
                                               HttpServletRequest httpRequest) {
        return noStore(authService.login(request.email(), request.password(), clientIpResolver.resolve(httpRequest)));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Rotate the refresh token",
            description = "Each refresh token works once. Presenting a used one revokes the whole login (401 "
                    + "REFRESH_TOKEN_REUSED).")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return noStore(authService.refresh(request.refreshToken()));
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Sign out", description = "Revokes the refresh token's login (token family).")
    public void logout(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody LogoutRequest request) {
        authService.logout(Actor.from(jwt).id(), request.refreshToken());
    }

    @PostMapping("/change-password")
    @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Change the password",
            description = "Required when mustChangePassword is true (every other endpoint answers 403 "
                    + "PASSWORD_CHANGE_REQUIRED until then). Revokes all existing tokens and returns new ones.")
    public ResponseEntity<TokenResponse> changePassword(@AuthenticationPrincipal Jwt jwt,
                                                        @Valid @RequestBody ChangePasswordRequest request) {
        return noStore(authService.changePassword(Actor.from(jwt).id(), request));
    }

    private static ResponseEntity<TokenResponse> noStore(TokenResponse body) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body);
    }
}
