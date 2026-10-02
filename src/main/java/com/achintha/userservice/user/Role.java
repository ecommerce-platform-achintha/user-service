package com.achintha.userservice.user;

/** One role per account (section 3.1). Super admin includes admin powers. */
public enum Role {
    ROLE_CUSTOMER,
    ROLE_MERCHANT,
    ROLE_ASSISTANT,
    ROLE_ADMIN,
    ROLE_SUPER_ADMIN,
    /** Internal service tokens only; never stored on a user (enforced by a DB check constraint). */
    ROLE_SERVICE;

    public boolean isAdmin() {
        return this == ROLE_ADMIN || this == ROLE_SUPER_ADMIN;
    }

    /** Roles that must provide a phone number and NIC. */
    public boolean requiresPhone() {
        return this == ROLE_CUSTOMER || this == ROLE_MERCHANT || this == ROLE_ASSISTANT;
    }

    public boolean hasStore() {
        return this == ROLE_MERCHANT || this == ROLE_ASSISTANT;
    }
}
