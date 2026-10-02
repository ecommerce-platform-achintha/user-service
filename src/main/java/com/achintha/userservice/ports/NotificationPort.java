package com.achintha.userservice.ports;

/** Sends SMS / email / in-app notifications (section 10). Implementations must never log message secrets. */
public interface NotificationPort {

    /**
     * @param recipientEmail where to send it
     * @param template       a template id, e.g. {@code MERCHANT_APPROVED}
     * @param subject        short, non-sensitive subject line
     */
    void notify(String recipientEmail, String template, String subject);
}
