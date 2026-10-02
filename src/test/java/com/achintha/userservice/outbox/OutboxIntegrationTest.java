package com.achintha.userservice.outbox;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.achintha.userservice.support.IntegrationTest;
import com.achintha.userservice.user.UserRequests.CustomerRegistrationRequest;
import com.achintha.userservice.user.UserService;
import com.achintha.userservice.user.User;
import com.jayway.jsonpath.JsonPath;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.test.EmbeddedKafkaBroker;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.kafka.test.utils.KafkaTestUtils;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.IllegalTransactionStateException;

/** Transactional outbox (section 9): written with the change, relayed to Kafka, consumers de-duplicate. */
@EmbeddedKafka(topics = OutboxIntegrationTest.TOPIC, partitions = 3)
@TestPropertySource(properties = "spring.kafka.bootstrap-servers=${spring.embedded.kafka.brokers}")
class OutboxIntegrationTest extends IntegrationTest {

    static final String TOPIC = "user-events";

    @Autowired
    private UserService userService;
    @Autowired
    private UserEventPublisher events;
    @Autowired
    private OutboxRepository outboxRepository;
    @Autowired
    private OutboxRelay relay;
    @Autowired
    private ProcessedEventStore processedEvents;
    @Autowired
    private EmbeddedKafkaBroker broker;

    @Test
    void eventIsWrittenInTheSameTransactionAsTheChange() {
        String email = uniqueEmail("rollback");
        long before = outboxRepository.count();

        assertThatThrownBy(() -> transactionTemplate.executeWithoutResult(tx -> {
            userService.registerCustomer(registration(email));
            assertThat(outboxRepository.count()).isEqualTo(before + 1); // visible inside the transaction
            throw new IllegalStateException("simulated failure after the change");
        })).isInstanceOf(IllegalStateException.class);

        // Rolled back together: no user, no event
        assertThat(userRepository.findByEmail(email)).isEmpty();
        assertThat(outboxRepository.count()).isEqualTo(before);

        // And events can never be recorded outside a transaction
        User someone = customer();
        assertThatThrownBy(() -> events.userRegistered(someone)).isInstanceOf(IllegalTransactionStateException.class);
    }

    @Test
    void relayPublishesPendingEventsToKafkaKeyedByUser() {
        String publicId = userService.registerCustomer(registration(uniqueEmail("relay"))).publicId();
        User user = userRepository.findByPublicId(publicId).orElseThrow();
        OutboxMessage pending = outboxRepository.findAllByAggregateIdOrderByIdAsc(user.getId()).getFirst();
        assertThat(pending.getPublishedAt()).isNull();

        try (Consumer<String, String> consumer = consumer()) {
            broker.consumeFromAnEmbeddedTopic(consumer, TOPIC);
            int published;
            do {
                published = relay.publishPending();
            } while (published > 0);

            OutboxMessage sent = outboxRepository.findById(pending.getId()).orElseThrow();
            assertThat(sent.getPublishedAt()).isNotNull();
            assertThat(sent.getAttempts()).isEqualTo(1);

            ConsumerRecord<String, String> record = find(consumer, pending.getEventId());
            assertThat(record.key()).isEqualTo(user.getId().toString());
            Map<String, Object> payload = JsonPath.read(record.value(), "$");
            assertThat(payload).containsEntry("eventType", "UserRegistered")
                    .containsEntry("eventId", pending.getEventId().toString())
                    .containsEntry("userId", user.getId().toString())
                    .containsEntry("publicId", user.getPublicId())
                    .containsEntry("role", "ROLE_CUSTOMER")
                    .containsEntry("status", "ACTIVE")
                    .containsKey("occurredAt")
                    .doesNotContainKey("email");
        }
        // Nothing left to publish twice
        assertThat(relay.publishPending()).isZero();
    }

    @Test
    void consumersDeduplicateByEventId() {
        UUID eventId = UUID.randomUUID();
        Boolean first = transactionTemplate.execute(tx -> processedEvents.markProcessed(eventId, "test-consumer"));
        Boolean again = transactionTemplate.execute(tx -> processedEvents.markProcessed(eventId, "test-consumer"));
        Boolean otherConsumer = transactionTemplate.execute(tx -> processedEvents.markProcessed(eventId, "other"));

        assertThat(first).isTrue();
        assertThat(again).isFalse();
        assertThat(otherConsumer).isTrue();
    }

    private Consumer<String, String> consumer() {
        Map<String, Object> props = KafkaTestUtils.consumerProps(broker, "outbox-test-" + UUID.randomUUID(), false);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        return new DefaultKafkaConsumerFactory<>(props, new StringDeserializer(), new StringDeserializer())
                .createConsumer();
    }

    private static ConsumerRecord<String, String> find(Consumer<String, String> consumer, UUID eventId) {
        List<ConsumerRecord<String, String>> seen = new ArrayList<>();
        long deadline = System.currentTimeMillis() + 15_000;
        while (System.currentTimeMillis() < deadline) {
            for (ConsumerRecord<String, String> record : KafkaTestUtils.getRecords(consumer, Duration.ofSeconds(2))) {
                seen.add(record);
                if (record.value().contains(eventId.toString())) {
                    return record;
                }
            }
        }
        throw new AssertionError("Event " + eventId + " not received; got " + seen.size() + " records");
    }

    private CustomerRegistrationRequest registration(String email) {
        return new CustomerRegistrationRequest(email, PASSWORD, "Out", "Box", uniqueNic(), uniquePhone());
    }
}
