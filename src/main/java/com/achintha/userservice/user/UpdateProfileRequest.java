package com.achintha.userservice.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Only profile fields are updatable here; email and password are deliberately absent. */
public record UpdateProfileRequest(
        @NotBlank @Size(max = 100) String firstName,
        @NotBlank @Size(max = 100) String lastName) {
}
