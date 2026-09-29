package com.achintha.userservice.auth;

import com.achintha.userservice.security.JwtService;
import com.achintha.userservice.security.JwtService.AccessToken;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtService jwtService;

    /** Returns 200 with an access token, or 401 (via the exception handler) on bad credentials. */
    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(request.email(), request.password()));
        User user = userService.findByEmail(request.email());
        AccessToken token = jwtService.generateAccessToken(user);
        return new TokenResponse(token.value(), "Bearer", token.expiresInSeconds(), token.expiresAt());
    }
}
