package com.achintha.userservice.user;

/** The two fields checked on every authenticated request (see {@code UserSecurityStateFilter}). */
public record SecuritySnapshot(long tokenVersion, boolean mustChangePassword) {
}
