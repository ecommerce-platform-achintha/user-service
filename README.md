# user-service

Spring Boot microservice for user registration, login (JWT) and user profiles/addresses.

- Java 25, Spring Boot 4.1.1, Spring Cloud 2025.1.3, Maven
- PostgreSQL via Spring Data JPA (`ddl-auto=update` for now; Flyway/Liquibase to follow)
- Config from the Config Server (`optional:configserver:http://localhost:8888`)
- Registers with Eureka (`http://localhost:8761/eureka/`)
- Port **8081**

## Prerequisites

Start these **before** user-service:

| Dependency | Default location | Notes |
|---|---|---|
| Config Server | `http://localhost:8888` | `../config-server`. Serves `config-repo/user-service.yml`, which holds the JWT secret |
| Eureka (service-registry) | `http://localhost:8761` | `../service-registry` |
| PostgreSQL | `localhost:5432`, db `userdb`, user/pass `userservice`/`userservice` | `docker compose up -d postgres` starts one with these defaults |

You also need JDK 25, Maven 3.9+, and Docker (for docker-compose and the Testcontainers integration test).

> **JWT secret.** `security.jwt.secret` has no local default. It comes from the Config Server
> (`config-repo/user-service.yml`), which resolves it from the `JWT_SECRET` environment variable
> of user-service and falls back to a dev-only value. If the Config Server is unreachable, the
> service **fails to start** because it has no signing key. Always set `JWT_SECRET`
> (≥ 32 characters) outside local development, for example: `export JWT_SECRET=$(openssl rand -base64 48)`.

## Configuration

Every setting can be overridden with an environment variable:

| Env var | Default | Purpose |
|---|---|---|
| `DB_HOST` / `DB_PORT` / `DB_NAME` | `localhost` / `5432` / `userdb` | JDBC URL parts |
| `DB_USERNAME` / `DB_PASSWORD` | `userservice` / `userservice` | DB credentials |
| `CONFIG_SERVER_URL` | `http://localhost:8888` | Config Server |
| `EUREKA_URL` | `http://localhost:8761/eureka/` | Eureka `defaultZone` |
| `JWT_SECRET` | dev value from config-repo | HS256 signing key (≥ 32 chars) |
| `SECURITY_JWT_ACCESSTOKENTTL` | `15m` | Access-token lifetime |

## Run locally

```bash
# 1. Config Server and Eureka (in their own terminals)
(cd ../config-server   && mvn spring-boot:run)
(cd ../service-registry && mvn spring-boot:run)

# 2. PostgreSQL only
docker compose up -d postgres

# 3. user-service
mvn spring-boot:run
```

Swagger UI: http://localhost:8081/swagger-ui.html. Use **Authorize** and paste the access token.
Health check: http://localhost:8081/actuator/health

## Run with docker-compose

This starts user-service and its PostgreSQL with one command. Config Server and Eureka must
still be running on the host. The container reaches them through `host.docker.internal`.

```bash
docker compose up --build
```

To point the container elsewhere, override `CONFIG_SERVER_URL` / `EUREKA_URL`
(e.g. `CONFIG_SERVER_URL=http://config-server:8888 docker compose up`).
Stop with `docker compose down` (add `-v` to also delete the database volume).

## API

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/users/register` | public | Create an account (201). The email is validated, and the password needs 8–72 characters with upper and lower case, a digit and a symbol |
| POST | `/api/auth/login` | public | Returns a 15-minute JWT access token, or 401 on bad credentials |
| GET | `/api/users/me` | Bearer | Current user's profile |
| PUT | `/api/users/me` | Bearer | Update `firstName` / `lastName` (email and password can't be changed here) |
| POST | `/api/users/me/addresses` | Bearer | Add an address (201) |
| GET | `/api/users/me/addresses` | Bearer | List the current user's addresses |

Swagger/OpenAPI (`/swagger-ui.html`, `/v3/api-docs`) and `/actuator/health` are public too.

Errors always use the same JSON shape:

```json
{
  "timestamp": "2026-09-24T16:14:54.468Z",
  "status": 400,
  "error": "Bad Request",
  "message": "Validation failed",
  "path": "/api/users/register",
  "fieldErrors": [{ "field": "email", "message": "must be a well-formed email address" }]
}
```

### Example curl session

```bash
# Register -> 201
curl -i -X POST http://localhost:8081/api/users/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"jane@example.com","password":"Str0ng!Passw0rd","firstName":"Jane","lastName":"Doe"}'

# Login -> {"accessToken":"...","tokenType":"Bearer","expiresIn":900,"expiresAt":"..."}
TOKEN=$(curl -s -X POST http://localhost:8081/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"jane@example.com","password":"Str0ng!Passw0rd"}' | jq -r .accessToken)

# Current user
curl -s http://localhost:8081/api/users/me -H "Authorization: Bearer $TOKEN"

# Update profile
curl -s -X PUT http://localhost:8081/api/users/me \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"firstName":"Janet","lastName":"Doe"}'

# Add and list addresses
curl -s -X POST http://localhost:8081/api/users/me/addresses \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"line1":"1 Main St","city":"Colombo","postalCode":"00100","country":"LK"}'
curl -s http://localhost:8081/api/users/me/addresses -H "Authorization: Bearer $TOKEN"
```

## Security notes

- Stateless: no HTTP session, CSRF disabled, no form login or basic auth.
- JWTs are issued and validated with Spring Security's built-in support (`spring-boot-starter-oauth2-resource-server`, Nimbus, HS256).
  `BearerTokenAuthenticationFilter` validates the signature, expiry and issuer, then fills the `SecurityContext`.
  The token `sub` is the user id, and the `roles` claim becomes the granted authorities.
- Passwords are hashed with BCrypt. No response DTO has a password field, and the request DTOs mask it in `toString()`.

## Tests

```bash
mvn clean package
```

- `JwtServiceTest`: token generation, claims, and rejection of expired, tampered, wrong-key and wrong-issuer tokens
- `PasswordHashingTest`: BCrypt hashing and salting; registration stores only the hash and never returns it
- `UserFlowIntegrationTest`: runs against a real PostgreSQL through Testcontainers (Docker required).
  It covers register → login → `GET /me`, plus profile update, addresses, validation errors and 401s.
