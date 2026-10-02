package com.achintha.userservice.common;

/** Shared Bean Validation patterns, so every DTO validates the same fields the same way. */
public final class Validation {

    /** E.164-ish: optional '+', no leading zero after it, 8 to 15 digits (e.g. +94771234567). Stored without spaces. */
    public static final String PHONE_REGEX = "^\\+?[1-9]\\d{7,14}$";
    public static final String PHONE_MESSAGE = "must be a phone number in international format, e.g. +94771234567";
    public static final String NIC_MESSAGE = "must be 9 digits followed by V or X, or 12 digits";
    /** Opaque keys of the mock document/image storage. */
    public static final String STORAGE_KEY_REGEX = "^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$";
    public static final int REASON_MAX = 500;

    private Validation() {
    }
}
