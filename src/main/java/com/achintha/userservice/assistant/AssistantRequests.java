package com.achintha.userservice.assistant;

import com.achintha.userservice.common.Nic;
import com.achintha.userservice.common.PasswordPolicy.ValidPassword;
import com.achintha.userservice.common.Validation;
import com.achintha.userservice.user.AssistantPermission;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Set;

public final class AssistantRequests {

    private AssistantRequests() {
    }

    public record CreateAssistantRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(max = 100) String firstName,
            @NotBlank @Size(max = 100) String lastName,
            @NotBlank @Pattern(regexp = Nic.REGEX, message = Validation.NIC_MESSAGE) String nic,
            @NotBlank @Pattern(regexp = Validation.PHONE_REGEX, message = Validation.PHONE_MESSAGE) String phone,
            @NotEmpty Set<@NotNull AssistantPermission> permissions,
            @NotBlank @ValidPassword String temporaryPassword) {

        @Override
        public String toString() {
            return "CreateAssistantRequest[email=" + email + ", permissions=" + permissions
                    + ", temporaryPassword=****]";
        }
    }

    public record UpdatePermissionsRequest(@NotEmpty Set<@NotNull AssistantPermission> permissions) {
    }
}
