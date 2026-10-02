package com.achintha.userservice.outbox;

/** Events on the {@code user-events} topic (section 9). The enum name is the wire {@code eventType}. */
public enum UserEventType {
    /** A customer, merchant, assistant or admin account was created. */
    UserRegistered,
    /** {@code status} changed (approval, rejection, resubmission, ban, grace end, unban). */
    UserStatusChanged,
    /** {@code tokenVersion} was incremented: consumers must reject tokens with an older {@code tv}. */
    UserSecurityChanged,
    /** Assistant created, permissions changed, banned, unbanned or removed. */
    AssistantChanged
}
