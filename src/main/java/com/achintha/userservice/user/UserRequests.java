package com.achintha.userservice.user;

import com.achintha.userservice.common.Nic;
import com.achintha.userservice.common.PasswordPolicy.ValidPassword;
import com.achintha.userservice.common.Validation;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;

/**
 * Registration and profile request bodies. Server-controlled fields (role, status, storeId, ...) do not exist here,
 * so they can never be set by a client. Passwords are masked in {@code toString()}.
 */
public final class UserRequests {

    private UserRequests() {
    }

    public record CustomerRegistrationRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @ValidPassword String password,
            @NotBlank @Size(max = 100) String firstName,
            @NotBlank @Size(max = 100) String lastName,
            @NotBlank @Pattern(regexp = Nic.REGEX, message = Validation.NIC_MESSAGE) String nic,
            @NotBlank @Pattern(regexp = Validation.PHONE_REGEX, message = Validation.PHONE_MESSAGE) String phone) {

        @Override
        public String toString() {
            return "CustomerRegistrationRequest[email=" + email + ", password=****]";
        }
    }

    public record MerchantRegistrationRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @ValidPassword String password,
            @NotBlank @Size(max = 100) String firstName,
            @NotBlank @Size(max = 100) String lastName,
            @NotBlank @Pattern(regexp = Nic.REGEX, message = Validation.NIC_MESSAGE) String nic,
            @NotBlank @Pattern(regexp = Validation.PHONE_REGEX, message = Validation.PHONE_MESSAGE) String phone,
            @NotBlank @Size(max = 150) String businessName,
            @NotEmpty @Size(max = 10) List<@NotBlank @Pattern(regexp = Validation.STORAGE_KEY_REGEX,
                    message = "must be a document storage key") String> documentKeys) {

        @Override
        public String toString() {
            return "MerchantRegistrationRequest[email=" + email + ", password=****, businessName=" + businessName
                    + "]";
        }
    }

    /** Merchant re-application after a rejection. */
    public record MerchantApplicationRequest(
            @NotBlank @Size(max = 150) String businessName,
            @NotEmpty @Size(max = 10) List<@NotBlank @Pattern(regexp = Validation.STORAGE_KEY_REGEX,
                    message = "must be a document storage key") String> documentKeys) {
    }

    /** Email, NIC, role and password cannot be changed here. */
    public record UpdateProfileRequest(
            @NotBlank @Size(max = 100) String firstName,
            @NotBlank @Size(max = 100) String lastName,
            @Pattern(regexp = Validation.PHONE_REGEX, message = Validation.PHONE_MESSAGE) String phone) {
    }
}
