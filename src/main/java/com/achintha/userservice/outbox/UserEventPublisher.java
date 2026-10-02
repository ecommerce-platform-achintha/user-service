package com.achintha.userservice.outbox;

import com.achintha.userservice.user.AssistantPermission;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserStatus;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

/**
 * Records {@code user-events} in the outbox, inside the caller's transaction ({@code MANDATORY}): the event is stored
 * if and only if the change commits. {@link OutboxRelay} publishes it to Kafka afterwards (at-least-once). Nothing is
 * ever sent to Kafka directly from business code.
 */
@Component
public class UserEventPublisher {

    private final OutboxRepository outboxRepository;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final String topic;

    public UserEventPublisher(OutboxRepository outboxRepository, ObjectMapper objectMapper, Clock clock,
                              @Value("${app.kafka.topics.user-events}") String topic) {
        this.outboxRepository = outboxRepository;
        this.objectMapper = objectMapper;
        this.clock = clock;
        this.topic = topic;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void userRegistered(User user) {
        append(base(UserEventType.UserRegistered, user, null, null));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void statusChanged(User user, UserStatus previousStatus) {
        append(base(UserEventType.UserStatusChanged, user, previousStatus, null));
    }

    /** Call after {@link User#incrementTokenVersion()}. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void securityChanged(User user, String change) {
        append(base(UserEventType.UserSecurityChanged, user, null, change));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void assistantChanged(User assistant, String change) {
        append(base(UserEventType.AssistantChanged, assistant, null, change));
    }

    private UserEvent base(UserEventType type, User user, UserStatus previousStatus, String change) {
        Instant now = clock.instant();
        List<String> permissions = user.getRole() == Role.ROLE_ASSISTANT
                ? user.effectivePermissions().stream().map(AssistantPermission::name).sorted().toList()
                : null;
        return new UserEvent(UUID.randomUUID(), type, now, user.getId(), user.getPublicId(), user.getRole(),
                user.getStatus(), previousStatus, user.getAssistantStatus(), user.getStoreId(),
                user.getTokenVersion(), permissions, user.getBanEffectiveAt(), change);
    }

    private void append(UserEvent event) {
        OutboxMessage message = new OutboxMessage();
        message.setEventId(event.eventId());
        message.setAggregateId(event.userId());
        message.setEventType(event.eventType().name());
        message.setTopic(topic);
        message.setMessageKey(event.userId().toString());
        message.setPayload(objectMapper.writeValueAsString(event));
        message.setCreatedAt(event.occurredAt());
        outboxRepository.save(message);
    }
}
