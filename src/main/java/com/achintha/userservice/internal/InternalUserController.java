package com.achintha.userservice.internal;

import com.achintha.userservice.address.AddressResponse;
import com.achintha.userservice.address.AddressService;
import com.achintha.userservice.exception.NotFoundException;
import com.achintha.userservice.internal.InternalResponses.Contact;
import com.achintha.userservice.internal.InternalResponses.SecurityState;
import com.achintha.userservice.user.UserRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Service-to-service reads ({@code ROLE_SERVICE} only; never routed by the gateway; not in the public docs). */
@RestController
@RequestMapping("/internal/users/{id}")
@PreAuthorize("hasAuthority('ROLE_SERVICE')")
@RequiredArgsConstructor
public class InternalUserController {

    private final UserRepository userRepository;
    private final AddressService addressService;

    /** Cache-miss fallback of every service's {@code SecurityStateFilter}. */
    @GetMapping("/security-state")
    @Transactional(readOnly = true)
    public SecurityState securityState(@PathVariable UUID id) {
        return userRepository.findById(id).map(SecurityState::from)
                .orElseThrow(() -> new NotFoundException("User not found"));
    }

    /** Address snapshot for checkout; 404 unless the address belongs to that user. */
    @GetMapping("/addresses/{addressPublicId}")
    public AddressResponse address(@PathVariable UUID id, @PathVariable String addressPublicId) {
        return addressService.get(id, addressPublicId);
    }

    @GetMapping("/contact")
    @Transactional(readOnly = true)
    public Contact contact(@PathVariable UUID id) {
        return userRepository.findById(id).map(Contact::from)
                .orElseThrow(() -> new NotFoundException("User not found"));
    }
}
