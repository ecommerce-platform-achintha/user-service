package com.achintha.userservice.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** No format checks beyond lengths: any mismatch must produce the same uniform "invalid email or password". */
public record LoginRequest(@NotBlank @Size(max = 254) String email, @NotBlank @Size(max = 128) String password) {

    @Override
    public String toString() {
        return "LoginRequest[email=" + email + ", password=****]";
    }
}
