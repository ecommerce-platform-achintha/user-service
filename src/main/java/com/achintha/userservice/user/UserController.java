package com.achintha.userservice.user;

import com.achintha.userservice.config.OpenApiConfig;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse register(@Valid @RequestBody RegisterRequest request) {
        return userService.register(request);
    }

    @GetMapping("/me")
    @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
    public UserResponse me(@AuthenticationPrincipal Jwt jwt) {
        return userService.getProfile(userId(jwt));
    }

    @PutMapping("/me")
    @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
    public UserResponse updateMe(@AuthenticationPrincipal Jwt jwt,
                                 @Valid @RequestBody UpdateProfileRequest request) {
        return userService.updateProfile(userId(jwt), request);
    }

    /** The token subject is the user's id (see JwtService). */
    public static UUID userId(Jwt jwt) {
        return UUID.fromString(jwt.getSubject());
    }
}
