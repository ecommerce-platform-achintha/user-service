package com.achintha.userservice.address;

import java.time.Instant;

public record AddressResponse(
        String publicId,
        String recipientName,
        String phone,
        String line1,
        String line2,
        String city,
        String district,
        String postalCode,
        String country,
        Instant updatedAt) {

    public static AddressResponse from(Address address) {
        return new AddressResponse(address.getPublicId(), address.getRecipientName(), address.getPhone(),
                address.getLine1(), address.getLine2(), address.getCity(), address.getDistrict(),
                address.getPostalCode(), address.getCountry(), address.getUpdatedAt());
    }
}
