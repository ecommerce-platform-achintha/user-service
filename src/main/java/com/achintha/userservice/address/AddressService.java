package com.achintha.userservice.address;

import com.achintha.userservice.user.UserService;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AddressService {

    private final AddressRepository addressRepository;
    private final UserService userService;

    @Transactional
    public AddressResponse addAddress(UUID userId, AddressRequest request) {
        Address address = new Address();
        address.setUser(userService.findUser(userId));
        address.setLine1(request.line1().trim());
        address.setLine2(request.line2() == null || request.line2().isBlank() ? null : request.line2().trim());
        address.setCity(request.city().trim());
        address.setPostalCode(request.postalCode().trim());
        address.setCountry(request.country().trim());
        return AddressResponse.from(addressRepository.save(address));
    }

    @Transactional(readOnly = true)
    public List<AddressResponse> listAddresses(UUID userId) {
        userService.findUser(userId); // 404 if the token's user no longer exists
        return addressRepository.findAllByUserId(userId).stream()
                .map(AddressResponse::from)
                .toList();
    }
}
