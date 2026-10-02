package com.achintha.userservice.admin;

import com.achintha.userservice.admin.AdminRequests.NoteRequest;
import com.achintha.userservice.admin.AdminRequests.ReasonRequest;
import com.achintha.userservice.common.PageResponse;
import com.achintha.userservice.common.Pagination;
import com.achintha.userservice.config.OpenApiConfig;
import com.achintha.userservice.merchant.MerchantApplicationService;
import com.achintha.userservice.security.Actor;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.UserResponses.AdminUserResponse;
import com.achintha.userservice.user.UserStatus;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Admin APIs (section 3.4: ROLE_ADMIN or ROLE_SUPER_ADMIN). Users are addressed by public id. */
@RestController
@RequestMapping("/api/admin")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
@PreAuthorize("hasAnyAuthority('ROLE_ADMIN','ROLE_SUPER_ADMIN')")
@RequiredArgsConstructor
@Tag(name = "Admin")
public class AdminController {

    static final Map<String, String> SORTABLE = Map.of(
            "createdAt", "createdAt", "email", "email", "lastName", "lastName", "status", "status",
            "statusChangedAt", "statusChangedAt");

    private final AdminUserService adminUserService;
    private final AccountStatusService accountStatusService;
    private final MerchantApplicationService merchantApplicationService;

    @GetMapping("/users")
    @Operation(summary = "Search users (filters: role, status, q on email/name/public id); max page size 100")
    public PageResponse<AdminUserResponse> users(@RequestParam(required = false) Role role,
                                                 @RequestParam(required = false) UserStatus status,
                                                 @RequestParam(required = false) String q,
                                                 @RequestParam(defaultValue = "0") int page,
                                                 @RequestParam(defaultValue = "20") int size,
                                                 @RequestParam(defaultValue = "createdAt,desc") String sort) {
        return adminUserService.search(role, status, q,
                Pagination.of(page, size, sort, SORTABLE, Pagination.MAX_ADMIN_SIZE));
    }

    @GetMapping("/users/{publicId}")
    @Operation(summary = "View one user (full NIC, real status including BAN_GRACE)")
    public AdminUserResponse user(@PathVariable String publicId) {
        return adminUserService.get(publicId);
    }

    @PostMapping("/users/{publicId}/assistant-ban")
    @Operation(summary = "Ban an assistant for misconduct (permanent NIC block)")
    public AdminUserResponse banAssistant(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                          @Valid @RequestBody ReasonRequest request) {
        return AdminUserResponse.from(accountStatusService.banAssistant(Actor.from(jwt), publicId,
                request.reason()));
    }

    @GetMapping("/merchants/pending")
    @Operation(summary = "Merchants waiting for approval")
    public PageResponse<AdminUserResponse> pendingMerchants(@RequestParam(defaultValue = "0") int page,
                                                            @RequestParam(defaultValue = "20") int size,
                                                            @RequestParam(defaultValue = "createdAt,asc")
                                                            String sort) {
        return adminUserService.pendingMerchants(
                Pagination.of(page, size, sort, SORTABLE, Pagination.MAX_ADMIN_SIZE));
    }

    @PostMapping("/merchants/{publicId}/approve")
    @Operation(summary = "Approve a pending merchant (optional note)")
    public AdminUserResponse approve(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                     @Valid @RequestBody(required = false) NoteRequest request) {
        merchantApplicationService.approve(Actor.from(jwt), publicId, request == null ? null : request.note());
        return adminUserService.get(publicId);
    }

    @PostMapping("/merchants/{publicId}/reject")
    @Operation(summary = "Reject a pending merchant (reason required, shown to the merchant)")
    public AdminUserResponse reject(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                    @Valid @RequestBody ReasonRequest request) {
        merchantApplicationService.reject(Actor.from(jwt), publicId, request.reason());
        return adminUserService.get(publicId);
    }

    @PostMapping("/merchants/{publicId}/ban")
    @Operation(summary = "Ban a merchant: silent BAN_GRACE for timers.ban-grace-days, then BANNED")
    public AdminUserResponse banMerchant(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                         @Valid @RequestBody ReasonRequest request) {
        return AdminUserResponse.from(accountStatusService.banMerchant(Actor.from(jwt), publicId,
                request.reason()));
    }

    @PostMapping("/merchants/{publicId}/unban")
    @Operation(summary = "Lift a merchant ban (grace or announced)")
    public AdminUserResponse unbanMerchant(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                           @Valid @RequestBody ReasonRequest request) {
        return AdminUserResponse.from(accountStatusService.unbanMerchant(Actor.from(jwt), publicId,
                request.reason()));
    }

    @PostMapping("/customers/{publicId}/ban")
    @Operation(summary = "Ban a customer immediately (can still sign in and view history)")
    public AdminUserResponse banCustomer(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                         @Valid @RequestBody ReasonRequest request) {
        return AdminUserResponse.from(accountStatusService.banCustomer(Actor.from(jwt), publicId,
                request.reason()));
    }

    @PostMapping("/customers/{publicId}/unban")
    @Operation(summary = "Lift a customer ban")
    public AdminUserResponse unbanCustomer(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                           @Valid @RequestBody ReasonRequest request) {
        return AdminUserResponse.from(accountStatusService.unbanCustomer(Actor.from(jwt), publicId,
                request.reason()));
    }
}
