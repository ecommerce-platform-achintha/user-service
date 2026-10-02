package com.achintha.userservice.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

/** Public API docs. {@code /internal/**} is excluded ({@code springdoc.paths-to-exclude}). */
@Configuration
@OpenAPIDefinition(info = @Info(title = "User Service API", version = "v2",
        description = "Identity provider of the marketplace: accounts, roles and statuses, merchant approvals, bans, "
                + "assistants, RS256 access tokens (JWKS at /.well-known/jwks.json) and refresh tokens. "
                + "Errors carry a stable 'code'."))
@SecurityScheme(name = OpenApiConfig.BEARER_AUTH, type = SecuritySchemeType.HTTP, scheme = "bearer",
        bearerFormat = "JWT")
public class OpenApiConfig {

    public static final String BEARER_AUTH = "bearerAuth";
}
