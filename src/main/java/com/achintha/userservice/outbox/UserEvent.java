package com.achintha.userservice.outbox;

import com.achintha.userservice.user.AssistantStatus;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.UserStatus;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * JSON payload of every {@code user-events} message, keyed by {@code userId}. Fields that do not apply to an event
 * are omitted. No PII beyond ids is published.
 *
 * @param status         the real status, including {@code BAN_GRACE} (consumers stop new orders during the grace)
 * @param previousStatus {@code UserStatusChanged} only
 * @param tokenVersion   {@code UserSecurityChanged}: tokens with a lower {@code tv} must be rejected
 * @param change         {@code AssistantChanged} / {@code UserSecurityChanged}: what happened (e.g. {@code BANNED})
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserEvent(
        UUID eventId,
        UserEventType eventType,
        Instant occurredAt,
        UUID userId,
        String publicId,
        Role role,
        UserStatus status,
        UserStatus previousStatus,
        AssistantStatus assistantStatus,
        UUID storeId,
        Long tokenVersion,
        List<String> permissions,
        Instant banEffectiveAt,
        String change) {
}
