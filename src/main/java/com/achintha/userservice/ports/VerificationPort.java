package com.achintha.userservice.ports;

/** Email and phone verification at registration (section 3.6). */
public interface VerificationPort {

    /** @return {@code true} if the email address is verified */
    boolean verifyEmail(String email);

    /** @return {@code true} if the phone number is verified */
    boolean verifyPhone(String phone);
}
