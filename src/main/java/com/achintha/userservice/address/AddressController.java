package com.achintha.userservice.address;

import com.achintha.userservice.common.PageResponse;
import com.achintha.userservice.common.Pagination;
import com.achintha.userservice.config.OpenApiConfig;
import com.achintha.userservice.security.Actor;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** The caller's own addresses; scoped by the token subject. */
@RestController
@RequestMapping("/api/users/me/addresses")
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
@PreAuthorize("hasAnyAuthority('ROLE_CUSTOMER','ROLE_MERCHANT','ROLE_ASSISTANT','ROLE_ADMIN','ROLE_SUPER_ADMIN')")
@RequiredArgsConstructor
@Tag(name = "Addresses")
public class AddressController {

    private static final Map<String, String> SORTABLE = Map.of("createdAt", "createdAt", "updatedAt", "updatedAt",
            "city", "city");

    private final AddressService addressService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public AddressResponse add(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody AddressRequest request) {
        return addressService.add(Actor.from(jwt).id(), request);
    }

    @GetMapping
    public PageResponse<AddressResponse> list(@AuthenticationPrincipal Jwt jwt,
                                              @RequestParam(defaultValue = "0") int page,
                                              @RequestParam(defaultValue = "20") int size,
                                              @RequestParam(defaultValue = "createdAt,desc") String sort) {
        return addressService.list(Actor.from(jwt).id(),
                Pagination.of(page, size, sort, SORTABLE, Pagination.MAX_SIZE));
    }

    @GetMapping("/{publicId}")
    public AddressResponse get(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId) {
        return addressService.get(Actor.from(jwt).id(), publicId);
    }

    @PutMapping("/{publicId}")
    public AddressResponse update(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId,
                                  @Valid @RequestBody AddressRequest request) {
        return addressService.update(Actor.from(jwt).id(), publicId, request);
    }

    @DeleteMapping("/{publicId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal Jwt jwt, @PathVariable String publicId) {
        addressService.delete(Actor.from(jwt).id(), publicId);
    }
}
