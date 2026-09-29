package com.achintha.userservice.user;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/** Public view of a user. Has no password field, so the hash can never be serialized. */
public record UserResponse(
        UUID id,
        String email,
        String firstName,
        String lastName,
        Set<Role> roles,
        Instant createdAt) {

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getEmail(), user.getFirstName(), user.getLastName(),
                user.getRoles().stream().collect(Collectors.toUnmodifiableSet()), user.getCreatedAt());
    }
}
