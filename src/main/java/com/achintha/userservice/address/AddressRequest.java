package com.achintha.userservice.address;

import com.achintha.userservice.common.Validation;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Create or replace an address. {@code country} defaults to Sri Lanka when omitted. */
public record AddressRequest(
        @NotBlank @Size(max = 150) String recipientName,
        @NotBlank @Pattern(regexp = Validation.PHONE_REGEX, message = Validation.PHONE_MESSAGE) String phone,
        @NotBlank @Size(max = 200) String line1,
        @Size(max = 200) String line2,
        @NotBlank @Size(max = 100) String city,
        @NotBlank @Size(max = 50) String district,
        @NotBlank @Size(max = 20) @Pattern(regexp = "^[A-Za-z0-9 -]{1,20}$", message = "must be a postal code")
        String postalCode,
        @Size(max = 100) String country) {
}
