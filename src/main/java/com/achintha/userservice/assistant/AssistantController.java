package com.achintha.userservice.assistant;

import com.achintha.userservice.admin.AdminRequests.ReasonRequest;
import com.achintha.userservice.assistant.AssistantRequests.CreateAssistantRequest;
import com.achintha.userservice.assistant.AssistantRequests.UpdatePermissionsRequest;
import com.achintha.userservice.common.PageResponse;
import com.achintha.userservice.common.Pagination;
import com.achintha.userservice.config.OpenApiConfig;
import com.achintha.userservice.security.Actor;
import com.achintha.userservice.user.UserResponses.AssistantResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Owner-only (ROLE_MERCHANT): assistants of the caller's own store. */
@RestController
@RequestMapping("/api/merchant/owner/assistants")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
@PreAuthorize("hasAuthority('ROLE_MERCHANT')")
@RequiredArgsConstructor
@Tag(name = "Merchant owner: assistants")
public class AssistantController {

    private static final Map<String, String> SORTABLE = Map.of(
            "createdAt", "createdAt", "lastName", "lastName", "email", "email", "assistantStatus", "assistantStatus");

    private final AssistantService assistantService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create an assistant (merchant must be ACTIVE; temporary password, forced change)")
    public AssistantResponse create(@AuthenticationPrincipal Jwt jwt,
                                    @Valid @RequestBody CreateAssistantRequest request) {
        return assistantService.create(Actor.from(jwt), request);
    }

    @GetMapping
    @Operation(summary = "List the store's assistants (NIC masked)")
    public PageResponse<AssistantResponse> list(@AuthenticationPrincipal Jwt jwt,
                                                @RequestParam(defaultValue = "0") int page,
                                                @RequestParam(defaultValue = "20") int size,
                                                @RequestParam(defaultValue = "createdAt,desc") String sort) {
        return assistantService.list(Actor.from(jwt),
                Pagination.of(page, size, sort, SORTABLE, Pagination.MAX_SIZE));
    }

    @GetMapping("/{publicId}")
    @Operation(summary = "View one assistant of the store")
    public AssistantResponse get(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId) {
        return assistantService.get(Actor.from(jwt), publicId);
    }

    @PutMapping("/{publicId}/permissions")
    @Operation(summary = "Replace the assistant's permissions (their current tokens are revoked)")
    public AssistantResponse updatePermissions(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                               @Valid @RequestBody UpdatePermissionsRequest request) {
        return assistantService.updatePermissions(Actor.from(jwt), publicId, request.permissions());
    }

    @PostMapping("/{publicId}/ban")
    @Operation(summary = "Ban the assistant (reason required; tokens revoked, NIC released)")
    public AssistantResponse ban(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                 @Valid @RequestBody ReasonRequest request) {
        return assistantService.ban(Actor.from(jwt), publicId, request.reason());
    }

    @PostMapping("/{publicId}/unban")
    @Operation(summary = "Lift the merchant's ban (409 if the NIC is now used by another store)")
    public AssistantResponse unban(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                   @Valid @RequestBody ReasonRequest request) {
        return assistantService.unban(Actor.from(jwt), publicId, request.reason());
    }

    @PostMapping("/{publicId}/remove")
    @Operation(summary = "Remove the assistant (reason required; final, tokens revoked, NIC released)")
    public AssistantResponse remove(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                    @Valid @RequestBody ReasonRequest request) {
        return assistantService.remove(Actor.from(jwt), publicId, request.reason());
    }
}
