package com.achintha.userservice.auth;

import java.time.Instant;

public record TokenResponse(String accessToken, String tokenType, long expiresIn, Instant expiresAt) {
}
