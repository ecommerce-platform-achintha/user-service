package com.achintha.userservice.user;

/**
 * Assistant sub-status. The NIC is released by {@link #BANNED_BY_MERCHANT} and {@link #REMOVED}, and stays blocked
 * by {@link #BANNED_BY_ADMIN} (section 13, point 5; partial unique index {@code ux_users_assistant_nic}).
 */
public enum AssistantStatus {
    ACTIVE,
    BANNED_BY_MERCHANT,
    BANNED_BY_ADMIN,
    REMOVED;

    public boolean holdsNic() {
        return this == ACTIVE || this == BANNED_BY_ADMIN;
    }
}
