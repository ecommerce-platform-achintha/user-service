package com.achintha.userservice.merchant;

import com.achintha.userservice.config.OpenApiConfig;
import com.achintha.userservice.security.Actor;
import com.achintha.userservice.user.UserRequests.MerchantApplicationRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** The merchant's own application. Owner only: assistants have no access. */
@RestController
@RequestMapping("/api/merchant/application")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
@PreAuthorize("hasAuthority('ROLE_MERCHANT')")
@RequiredArgsConstructor
@Tag(name = "Merchant application")
public class MerchantApplicationController {

    private final MerchantApplicationService service;

    @GetMapping
    @Operation(summary = "Application status, visible reason and remaining attempts")
    public MerchantApplicationResponse view(@AuthenticationPrincipal Jwt jwt) {
        return service.view(Actor.from(jwt));
    }

    @PostMapping("/resubmit")
    @Operation(summary = "Re-apply after a rejection (limited by merchant.max-application-attempts)")
    public MerchantApplicationResponse resubmit(@AuthenticationPrincipal Jwt jwt,
                                                @Valid @RequestBody MerchantApplicationRequest request) {
        return service.resubmit(Actor.from(jwt), request.businessName(), request.documentKeys());
    }
}
