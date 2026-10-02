package com.achintha.userservice.user;

import com.achintha.userservice.config.OpenApiConfig;
import com.achintha.userservice.security.Actor;
import com.achintha.userservice.user.UserRequests.CustomerRegistrationRequest;
import com.achintha.userservice.user.UserRequests.MerchantRegistrationRequest;
import com.achintha.userservice.user.UserRequests.UpdateProfileRequest;
import com.achintha.userservice.user.UserResponses.ProfileResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
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
@Tag(name = "Users")
public class UserController {

    static final String ANY_USER = "hasAnyAuthority('ROLE_CUSTOMER','ROLE_MERCHANT','ROLE_ASSISTANT','ROLE_ADMIN',"
            + "'ROLE_SUPER_ADMIN')";

    private final UserService userService;

    @PostMapping("/register/customer")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Register a customer (ACTIVE immediately)")
    public ProfileResponse registerCustomer(@Valid @RequestBody CustomerRegistrationRequest request) {
        return userService.registerCustomer(request);
    }

    @PostMapping("/register/merchant")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Register a merchant (PENDING_APPROVAL until an admin approves)")
    public ProfileResponse registerMerchant(@Valid @RequestBody MerchantRegistrationRequest request) {
        return userService.registerMerchant(request);
    }

    @GetMapping("/me")
    @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
    @PreAuthorize(ANY_USER)
    @Operation(summary = "The caller's profile, status, visible status reason and mustChangePassword")
    public ProfileResponse me(@AuthenticationPrincipal Jwt jwt) {
        return userService.getProfile(Actor.from(jwt).id());
    }

    @PutMapping("/me")
    @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
    @PreAuthorize(ANY_USER)
    @Operation(summary = "Update names and phone (email, NIC and role cannot be changed here)")
    public ProfileResponse updateMe(@AuthenticationPrincipal Jwt jwt,
                                    @Valid @RequestBody UpdateProfileRequest request) {
        return userService.updateProfile(Actor.from(jwt).id(), request);
    }
}
