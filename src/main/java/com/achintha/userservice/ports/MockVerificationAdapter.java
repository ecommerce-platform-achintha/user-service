package com.achintha.userservice.ports;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** Always verifies; logs only (with the email and phone masked). */
@Slf4j
@Component
@ConditionalOnProperty(name = "app.ports.verification", havingValue = "mock", matchIfMissing = true)
public class MockVerificationAdapter implements VerificationPort {

    @Override
    public boolean verifyEmail(String email) {
        log.info("[mock verification] email {} verified", MockNotificationAdapter.maskEmail(email));
        return true;
    }

    @Override
    public boolean verifyPhone(String phone) {
        String masked = phone == null || phone.length() < 3 ? "***" : "***" + phone.substring(phone.length() - 3);
        log.info("[mock verification] phone {} verified", masked);
        return true;
    }
}
