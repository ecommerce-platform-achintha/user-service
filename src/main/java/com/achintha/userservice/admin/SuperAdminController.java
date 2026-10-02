package com.achintha.userservice.admin;

import com.achintha.userservice.admin.AdminRequests.CreateAdminRequest;
import com.achintha.userservice.admin.AdminRequests.ReasonRequest;
import com.achintha.userservice.common.PageResponse;
import com.achintha.userservice.common.Pagination;
import com.achintha.userservice.config.OpenApiConfig;
import com.achintha.userservice.security.Actor;
import com.achintha.userservice.user.UserResponses.AdminUserResponse;
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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Admin management, super admin only. The super admin account itself is not reachable through any endpoint. */
@RestController
@RequestMapping("/api/super-admin/admins")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
@PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
@RequiredArgsConstructor
@Tag(name = "Super admin")
public class SuperAdminController {

    private final AdminUserService adminUserService;
    private final AccountStatusService accountStatusService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create an admin with a temporary password (must be changed at first sign-in)")
    public AdminUserResponse create(@AuthenticationPrincipal Jwt jwt,
                                    @Valid @RequestBody CreateAdminRequest request) {
        return adminUserService.createAdmin(Actor.from(jwt), request);
    }

    @GetMapping
    @Operation(summary = "List admins")
    public PageResponse<AdminUserResponse> list(@RequestParam(defaultValue = "0") int page,
                                                @RequestParam(defaultValue = "20") int size,
                                                @RequestParam(defaultValue = "createdAt,desc") String sort) {
        return adminUserService.admins(
                Pagination.of(page, size, sort, AdminController.SORTABLE, Pagination.MAX_ADMIN_SIZE));
    }

    @PostMapping("/{publicId}/ban")
    @Operation(summary = "Ban an admin (reason required; sign-in refused, all tokens revoked)")
    public AdminUserResponse ban(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                 @Valid @RequestBody ReasonRequest request) {
        return AdminUserResponse.from(accountStatusService.banAdmin(Actor.from(jwt), publicId, request.reason()));
    }

    @PostMapping("/{publicId}/unban")
    @Operation(summary = "Lift an admin ban")
    public AdminUserResponse unban(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                   @Valid @RequestBody ReasonRequest request) {
        return AdminUserResponse.from(accountStatusService.unbanAdmin(Actor.from(jwt), publicId,
                request.reason()));
    }
}
