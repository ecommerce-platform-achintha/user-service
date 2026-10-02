package com.achintha.userservice.user;

import com.achintha.userservice.exception.ApiException;
import com.achintha.userservice.exception.EmailAlreadyExistsException;
import com.achintha.userservice.exception.ErrorCode;
import org.springframework.dao.DataIntegrityViolationException;

/**
 * Translates unique-index violations that slipped past the pre-checks (concurrent requests) into the same API errors
 * the pre-checks produce.
 */
public final class UniqueConstraints {

    public static final String NIC_IN_USE_MESSAGE = "This NIC is already registered to an assistant of another store";

    private UniqueConstraints() {
    }

    public static RuntimeException translate(DataIntegrityViolationException e) {
        String message = String.valueOf(e.getMostSpecificCause().getMessage());
        if (message.contains("ux_users_email")) {
            return new EmailAlreadyExistsException();
        }
        if (message.contains("ux_users_assistant_nic")) {
            return ApiException.conflict(ErrorCode.NIC_ALREADY_ASSIGNED, NIC_IN_USE_MESSAGE);
        }
        return e;
    }
}
