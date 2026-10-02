package com.achintha.userservice.user;

/** Account status (section 3.1). */
public enum UserStatus {
    ACTIVE,
    /** Merchant only: waiting for admin approval. */
    PENDING_APPROVAL,
    /** Merchant only: application rejected; may re-apply up to merchant.max-application-attempts. */
    REJECTED,
    /** Merchant only: banned but silent for timers.ban-grace-days; never shown to the merchant. */
    BAN_GRACE,
    BANNED
}
