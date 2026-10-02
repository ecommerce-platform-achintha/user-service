package com.achintha.userservice.config;

import java.util.Arrays;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Refuses to start outside the {@code local} profile when a service client still uses the committed
 * {@code LOCAL-DEV-ONLY} placeholder secret (config-server README).
 */
@Component
public class InternalClientSecretGuard implements InitializingBean {

    static final String PLACEHOLDER_PREFIX = "LOCAL-DEV-ONLY";

    private final InternalAuthProperties properties;
    private final Environment environment;

    public InternalClientSecretGuard(InternalAuthProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @Override
    public void afterPropertiesSet() {
        boolean local = Arrays.asList(environment.getActiveProfiles()).contains("local");
        if (local) {
            return;
        }
        for (InternalAuthProperties.Client client : properties.clients()) {
            if (client.clientSecret().startsWith(PLACEHOLDER_PREFIX)) {
                throw new IllegalStateException("Service client '" + client.clientId()
                        + "' uses the local-dev placeholder secret outside the local profile; set its "
                        + "SERVICE_CLIENT_SECRET_<NAME> environment variable");
            }
        }
    }
}
