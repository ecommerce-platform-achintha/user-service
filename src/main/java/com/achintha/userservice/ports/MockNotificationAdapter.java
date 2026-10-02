package com.achintha.userservice.ports;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** Logs instead of sending; always succeeds. The recipient is masked in the log. */
@Slf4j
@Component
@ConditionalOnProperty(name = "app.ports.notification", havingValue = "mock", matchIfMissing = true)
public class MockNotificationAdapter implements NotificationPort {

    @Override
    public void notify(String recipientEmail, String template, String subject) {
        log.info("[mock notification] template={} to={} subject={}", template, maskEmail(recipientEmail), subject);
    }

    static String maskEmail(String email) {
        if (email == null) {
            return null;
        }
        int at = email.indexOf('@');
        return at <= 1 ? "***" + email.substring(Math.max(at, 0)) : email.charAt(0) + "***" + email.substring(at);
    }
}
