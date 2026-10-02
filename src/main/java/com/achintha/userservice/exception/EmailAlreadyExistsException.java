package com.achintha.userservice.exception;

import org.springframework.http.HttpStatus;

public class EmailAlreadyExistsException extends ApiException {

    public EmailAlreadyExistsException() {
        super(HttpStatus.CONFLICT, ErrorCode.EMAIL_ALREADY_EXISTS, "An account with this email already exists");
    }
}
