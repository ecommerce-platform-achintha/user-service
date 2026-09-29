package com.achintha.userservice.address;

import java.util.UUID;

public record AddressResponse(
        UUID id,
        UUID userId,
        String line1,
        String line2,
        String city,
        String postalCode,
        String country) {

    public static AddressResponse from(Address address) {
        return new AddressResponse(address.getId(), address.getUser().getId(), address.getLine1(),
                address.getLine2(), address.getCity(), address.getPostalCode(), address.getCountry());
    }
}
