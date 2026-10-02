package com.achintha.userservice.admin;

import com.achintha.userservice.common.Nic;
import com.achintha.userservice.common.PasswordPolicy.ValidPassword;
import com.achintha.userservice.common.Validation;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public final class AdminRequests {

    private AdminRequests() {
    }

    /** Ban, unban, reject: the reason is mandatory and shown to the user once visible. */
    public record ReasonRequest(@NotBlank @Size(max = Validation.REASON_MAX) String reason) {
    }

    /** Approve: an optional note. */
    public record NoteRequest(@Size(max = Validation.REASON_MAX) String note) {
    }

    /** Super admin creates an admin with a temporary password (changed at first login). */
    public record CreateAdminRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(max = 100) String firstName,
            @NotBlank @Size(max = 100) String lastName,
            @NotBlank @Pattern(regexp = Nic.REGEX, message = Validation.NIC_MESSAGE) String nic,
            @NotBlank @Pattern(regexp = Validation.PHONE_REGEX, message = Validation.PHONE_MESSAGE) String phone,
            @NotBlank @ValidPassword String temporaryPassword) {

        @Override
        public String toString() {
            return "CreateAdminRequest[email=" + email + ", temporaryPassword=****]";
        }
    }
}
