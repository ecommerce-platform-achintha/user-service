package com.achintha.userservice.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank @Email @Size(max = 254) String email,

        // BCrypt only uses the first 72 bytes, hence the upper bound.
        @NotBlank
        @Size(min = 8, max = 72, message = "must be between 8 and 72 characters")
        @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).*$",
                message = "must contain an uppercase letter, a lowercase letter, a digit and a special character")
        String password,

        @NotBlank @Size(max = 100) String firstName,
        @NotBlank @Size(max = 100) String lastName) {

    @Override
    public String toString() {
        return "RegisterRequest[email=" + email + ", password=****, firstName=" + firstName
                + ", lastName=" + lastName + "]";
    }
}
