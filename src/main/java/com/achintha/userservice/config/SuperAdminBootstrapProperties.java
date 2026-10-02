package com.achintha.userservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** {@code SUPER_ADMIN_EMAIL} / {@code SUPER_ADMIN_INITIAL_PASSWORD} (section 3.5). Blank means "not set". */
@ConfigurationProperties("bootstrap.super-admin")
public record SuperAdminBootstrapProperties(String email, String initialPassword) {

    public boolean isComplete() {
        return email != null && !email.isBlank() && initialPassword != null && !initialPassword.isBlank();
    }

    @Override
    public String toString() {
        return "SuperAdminBootstrapProperties[email=" + email + ", initialPassword=****]";
    }
}
