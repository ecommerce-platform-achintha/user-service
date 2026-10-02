package com.achintha.userservice.internal;

import com.achintha.userservice.user.AssistantPermission;
import com.achintha.userservice.user.AssistantStatus;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserStatus;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.UUID;

/** Service-to-service responses. Internal APIs may carry UUIDs (section 1). */
public final class InternalResponses {

    private InternalResponses() {
    }

    /**
     * What other services cache to validate tokens: the real status (including {@code BAN_GRACE}), role, token
     * version ({@code tv}), store and permissions ({@code perms}, assistants only).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SecurityState(
            UUID userId,
            String publicId,
            Role role,
            UserStatus status,
            AssistantStatus assistantStatus,
            long tv,
            UUID storeId,
            List<String> perms) {

        static SecurityState from(User user) {
            List<String> perms = user.isAssistant()
                    ? user.effectivePermissions().stream().map(AssistantPermission::name).sorted().toList()
                    : null;
            return new SecurityState(user.getId(), user.getPublicId(), user.getRole(), user.getStatus(),
                    user.getAssistantStatus(), user.getTokenVersion(), user.getStoreId(), perms);
        }
    }

    /** Contact data for order-service (order display, courier hand-over). */
    public record Contact(UUID userId, String publicId, String firstName, String lastName, String phone) {

        static Contact from(User user) {
            return new Contact(user.getId(), user.getPublicId(), user.getFirstName(), user.getLastName(),
                    user.getPhone());
        }
    }
}
