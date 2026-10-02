# user-service

Identity provider of the marketplace: accounts, roles, statuses, merchant approvals, bans, assistants, RS256 access
tokens (JWKS), refresh tokens and service tokens. The contract is [`docs/marketplace-design.md`](docs/marketplace-design.md)
(sections 0, 1, 3, 7, 9, 10 and 11 apply here).

- Java 25, Spring Boot 4.1.1, Spring Cloud 2025.1.3, Maven
- PostgreSQL, schema managed by **Flyway** (`src/main/resources/db/migration`), `ddl-auto=validate`
- Kafka topic `user-events`, published through a transactional outbox
- Config from the Config Server (`optional:configserver:http://localhost:8888`), registers with Eureka
- Port **8081**

## Prerequisites

| Dependency | Default location | Notes |
|---|---|---|
| Config Server | `http://localhost:8888` | `../config-server`, serves `config-repo/user-service.yml` |
| Eureka (service-registry) | `http://localhost:8761` | `../service-registry` |
| PostgreSQL | `localhost:5432`, db `userdb`, user/pass `userservice` | `docker compose up -d postgres` |
| Kafka | `localhost:9092` | the shared broker from `../order-service` (`docker compose up -d kafka`). Optional: without it, events wait in the `outbox` table |

JDK 25, Maven 3.9+ and Docker (docker-compose, Testcontainers) are needed too.

**The database is replaced once.** Flyway's `V1__init.sql` creates the new schema, so remove the old Hibernate-made
volume before the first start: `docker compose down -v`.

## Local RSA keys

Access tokens are signed with RS256. The private key exists only in user-service; everyone else verifies with the
public key from `GET /.well-known/jwks.json`. Generate a dev key pair once, in this project root (`keys/` and
`*.pem` are git- and docker-ignored, never commit a key):

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/jwt-private.pem
openssl pkey -in keys/jwt-private.pem -pubout -out keys/jwt-public.pem
```

With the `local` profile (`SPRING_PROFILES_ACTIVE=local`), the Config Server points at these files. Otherwise set
the variables to the PEM text or to a resource location:

```bash
export JWT_PRIVATE_KEY="$(cat keys/jwt-private.pem)"      # or file:/run/secrets/jwt-private.pem
export JWT_PUBLIC_KEY="$(cat keys/jwt-public.pem)"
export JWT_KEY_ID=user-service-rs256-1                    # change it whenever the key pair is rotated
```

The private key must be PKCS#8 (`BEGIN PRIVATE KEY`, what `openssl genpkey` writes) and at least 2048 bits; startup
fails if it is missing, too small or does not match the public key.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `DB_HOST` / `DB_PORT` / `DB_NAME` | `localhost` / `5432` / `userdb` | JDBC URL parts |
| `DB_USERNAME` / `DB_PASSWORD` | `userservice` / `userservice` | DB credentials |
| `CONFIG_SERVER_URL` | `http://localhost:8888` | Config Server |
| `EUREKA_URL` | `http://localhost:8761/eureka/` | Eureka `defaultZone` |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka for the outbox relay |
| `KAFKA_TOPIC_USER_EVENTS` | `user-events` | topic name |
| `JWT_PRIVATE_KEY` | none (**required**, secret) | RS256 private key, PEM text or resource location |
| `JWT_PUBLIC_KEY` | none (**required**) | matching public key |
| `JWT_KEY_ID` | `user-service-rs256-1` | `kid` of tokens and JWKS |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `user-service` / `marketplace` | `iss` / `aud` of every token |
| `JWT_CLOCK_SKEW_SECONDS` | `30` | `exp`/`nbf` tolerance |
| `SUPER_ADMIN_EMAIL` | none | bootstrap of the unique super admin (first start) |
| `SUPER_ADMIN_INITIAL_PASSWORD` | none (secret) | same; min. 12 characters, must be changed at first sign-in, never logged |
| `SERVICE_CLIENT_SECRET_STORE` / `_PRODUCT` / `_ORDER` | `local` profile: dev placeholder; otherwise **required** | client secrets for `POST /internal/auth/service-token` (same value in the calling service) |
| `AUTH_TRUST_FORWARDED_FOR` | `false` | `true` behind the api-gateway: the login throttle uses the last `X-Forwarded-For` hop as client IP |
| `AUTH_IP_MAX_FAILED_LOGINS` | `20` | failed logins per client IP before that IP is locked for `auth.lockout-minutes` |
| `SHEDLOCK_ENABLED` | `true` | scheduler locks (one replica runs each job) |

Other settings (Config Server or `application.yml`): `auth.access-token-minutes` (10), `auth.refresh-days` (14),
`auth.max-failed-logins` (5), `auth.lockout-minutes` (15), `timers.ban-grace-days` (14),
`merchant.max-application-attempts` (3), `security.internal.service-token-minutes` (5),
`app.scheduling.ban-enforcement.interval` (PT5M), `app.outbox.relay-interval` (PT1S), `app.outbox.batch-size` (100),
`app.max-addresses-per-user` (20), `app.ports.notification` / `app.ports.verification` (`mock`).

The service refuses to start outside the `local` profile when a service client still uses the `LOCAL-DEV-ONLY`
placeholder secret.

## Run locally

```bash
(cd ../config-server && mvn spring-boot:run)          # own terminal
(cd ../service-registry && mvn spring-boot:run)       # own terminal
docker compose up -d postgres
export SUPER_ADMIN_EMAIL=root@example.com SUPER_ADMIN_INITIAL_PASSWORD='choose-a-long-passphrase'
SPRING_PROFILES_ACTIVE=local mvn spring-boot:run
```

Swagger UI: http://localhost:8081/swagger-ui.html (use **Authorize** with an access token). Health:
http://localhost:8081/actuator/health. Only `health` and `info` are exposed.

## Run with docker-compose

```bash
cat > .env <<'EOF'                 # git-ignored
SUPER_ADMIN_EMAIL=root@example.com
SUPER_ADMIN_INITIAL_PASSWORD=choose-a-long-passphrase
EOF
JWT_PRIVATE_KEY="$(cat keys/jwt-private.pem)" JWT_PUBLIC_KEY="$(cat keys/jwt-public.pem)" docker compose up --build
```

Config Server, Eureka and Kafka are expected on the host (`host.docker.internal`).

## Roles, statuses and sign-in rules

One role per account: `ROLE_CUSTOMER`, `ROLE_MERCHANT`, `ROLE_ASSISTANT`, `ROLE_ADMIN`, `ROLE_SUPER_ADMIN`
(`ROLE_SERVICE` exists only in service tokens). Super admin includes admin powers.

| Status | Applies to | Sign-in | Reason shown |
|---|---|---|---|
| `ACTIVE` | all | yes | no |
| `PENDING_APPROVAL` | merchant | yes | no |
| `REJECTED` | merchant | yes (can re-apply up to 3 applications in total) | yes |
| `BAN_GRACE` | merchant | yes; shown to the merchant as `ACTIVE`, also in the token | never |
| `BANNED` | customer | yes (view only) | yes |
| `BANNED` | merchant | yes (history only) | once announced (day 14) |
| `BANNED` | admin | **no** (403 `ACCOUNT_BANNED` with the reason) | in the error |

Assistants also have an `assistantStatus`: `ACTIVE`, `BANNED_BY_MERCHANT`, `BANNED_BY_ADMIN`, `REMOVED`. Banned or
removed assistants and assistants whose merchant is `BANNED` (announced, not during the grace period) cannot sign in.
An assistant's NIC can belong to one store at a time: it is released by a merchant ban or removal and stays blocked
for good after an admin ban (partial unique index `ux_users_assistant_nic`).

**Merchant ban timeline.** An admin ban sets `BAN_GRACE` with `banEffectiveAt = now + 14 days`; nothing changes for
the merchant or the assistants, and `UserStatusChanged(BAN_GRACE)` lets the other services stop new orders. Every 5
minutes a ShedLock-guarded job turns due merchants into `BANNED`, sets `banAnnouncedAt`, reveals the reason, signs the
merchant and every assistant out (token version + refresh tokens) and emits `UserStatusChanged` and
`UserSecurityChanged`.

**Tokens.** Access token: RS256, 10 minutes, claims exactly `sub, pid, role, status, storeId, perms, tv, iss, aud,
iat, exp, jti` (`storeId` for merchants/assistants, `perms` for assistants only). Refresh token: opaque, stored as a
SHA-256 hash, 14 days, rotated on every use; presenting a used token revokes the whole login (token family).
`tokenVersion` (`tv`) is incremented on ban, unban, permission change, assistant removal and password change; every
request to this service checks it against the database, and each increment emits `UserSecurityChanged` for the other
services' caches.

**Passwords.** Argon2id (`DelegatingPasswordEncoder`, bcrypt hashes still verify and are re-hashed on the next
sign-in). At least 12 characters, at most 128, not on a small deny list. Accounts created by someone else (admins,
assistants, the super admin) must change the password first: until then every endpoint except
`/api/auth/change-password` and `/api/auth/logout` answers 403 `PASSWORD_CHANGE_REQUIRED`.

**Lockout.** 5 wrong passwords lock the account for 15 minutes (unknown emails are locked the same way, so the 429
does not reveal which accounts exist); client IPs have their own limit. Wrong email and wrong password give the same
401 `INVALID_CREDENTIALS`.

## API

All `/api` lists are paged: `page`, `size` (max 50, admin lists 100), `sort=field,asc|desc` (whitelisted fields).
Users are addressed by `publicId` (`USR-YYMM-XXXXXX`), addresses by `ADR-YYMM-XXXXXX`; UUIDs only appear in tokens,
events and internal APIs.

| Method | Path | Who | Description |
|---|---|---|---|
| GET | `/.well-known/jwks.json` | public | JWKS (public key only, `Cache-Control: public, max-age=300`) |
| POST | `/api/auth/login` | public | `{email, password}` → tokens + `publicId, role, status, statusReason, mustChangePassword` |
| POST | `/api/auth/refresh` | public | `{refreshToken}` → new token pair (rotation, reuse detection) |
| POST | `/api/auth/logout` | signed in | `{refreshToken}` → revokes that login (204) |
| POST | `/api/auth/change-password` | signed in | `{currentPassword, newPassword}` → revokes all tokens, returns new ones |
| POST | `/api/users/register/customer` | public | email, password, names, NIC, phone → `ACTIVE` |
| POST | `/api/users/register/merchant` | public | same + `businessName`, `documentKeys[]` → `PENDING_APPROVAL`, `storeId` assigned |
| GET / PUT | `/api/users/me` | signed in | own profile (full NIC); PUT changes names and phone only |
| GET / POST | `/api/users/me/addresses` | signed in | list (paged) / add (recipient, phone, lines, city, district, postal code, country) |
| GET / PUT / DELETE | `/api/users/me/addresses/{publicId}` | signed in | own addresses only (others: 404) |
| GET | `/api/merchant/application` | merchant | application status, visible reason, attempts |
| POST | `/api/merchant/application/resubmit` | merchant | re-apply after a rejection (`APPLICATION_LIMIT_REACHED` after 3) |
| GET / POST | `/api/merchant/owner/assistants` | merchant (owner) | list (NIC masked) / create (merchant must be active; temporary password) |
| GET | `/api/merchant/owner/assistants/{publicId}` | merchant (owner) | one assistant of the own store |
| PUT | `/api/merchant/owner/assistants/{publicId}/permissions` | merchant (owner) | `{permissions[]}` |
| POST | `/api/merchant/owner/assistants/{publicId}/ban` / `unban` / `remove` | merchant (owner) | `{reason}` |
| GET | `/api/admin/users` | admin | search: `role`, `status`, `q` (email, name, public id) |
| GET | `/api/admin/users/{publicId}` | admin | full view (real status incl. `BAN_GRACE`, full NIC) |
| POST | `/api/admin/users/{publicId}/assistant-ban` | admin | `{reason}`, permanent NIC block |
| GET | `/api/admin/merchants/pending` | admin | merchants waiting for approval |
| POST | `/api/admin/merchants/{publicId}/approve` | admin | optional `{note}` |
| POST | `/api/admin/merchants/{publicId}/reject` / `ban` / `unban` | admin | `{reason}` |
| POST | `/api/admin/customers/{publicId}/ban` / `unban` | admin | `{reason}` |
| GET / POST | `/api/super-admin/admins` | super admin | list / create (`email, names, nic, phone, temporaryPassword`) |
| POST | `/api/super-admin/admins/{publicId}/ban` / `unban` | super admin | `{reason}` (the super admin itself is never a target) |
| POST | `/internal/auth/service-token` | services | `{clientId, clientSecret}` → `ROLE_SERVICE` token (5 min, `svc` claim) |
| GET | `/internal/users/{id}/security-state` | `ROLE_SERVICE` | `userId, publicId, role, status, assistantStatus, tv, storeId, perms` |
| GET | `/internal/users/{id}/addresses/{addressPublicId}` | `ROLE_SERVICE` | the user's address (404 if not theirs) |
| GET | `/internal/users/{id}/contact` | `ROLE_SERVICE` | `userId, publicId, firstName, lastName, phone` |

`/internal/**` is excluded from the OpenAPI document and must never be routed by the gateway. Everything not listed
is denied (deny-by-default). Every privileged mutation writes an append-only `audit_log` row (NIC masked, no hashes).

Errors keep the usual shape plus a stable `code`:

```json
{
  "timestamp": "2026-10-01T06:42:25.401Z",
  "status": 403,
  "error": "Forbidden",
  "code": "ACCOUNT_BANNED",
  "message": "Your account has been banned. Reason: Data leak",
  "path": "/api/auth/login"
}
```

Codes: `VALIDATION_FAILED, MALFORMED_REQUEST, BAD_REQUEST, INVALID_SORT, NOT_FOUND, METHOD_NOT_ALLOWED,
UNSUPPORTED_MEDIA_TYPE, CONCURRENT_MODIFICATION, INTERNAL_ERROR, UNAUTHORIZED, ACCESS_DENIED, INVALID_CREDENTIALS,
TOO_MANY_LOGIN_ATTEMPTS, ACCOUNT_BANNED, ACCOUNT_REMOVED, MERCHANT_BANNED, PASSWORD_CHANGE_REQUIRED, TOKEN_REVOKED,
INVALID_REFRESH_TOKEN, REFRESH_TOKEN_REUSED, INVALID_CLIENT_CREDENTIALS, WEAK_PASSWORD, PASSWORD_REUSED,
EMAIL_ALREADY_EXISTS, NIC_ALREADY_ASSIGNED, INVALID_STATUS_TRANSITION, MERCHANT_NOT_ACTIVE, APPLICATION_LIMIT_REACHED,
ADDRESS_LIMIT_REACHED`.

## Events (`user-events`)

Written to the `outbox` table in the same transaction as the change; a relay (every second, ShedLock) publishes them
in order, keyed by the user's UUID, and marks them published (at-least-once: consumers de-duplicate by `eventId`).

| eventType | When |
|---|---|
| `UserRegistered` | customer, merchant, assistant, admin or super admin created |
| `UserStatusChanged` | approve, reject, resubmit, merchant ban (`BAN_GRACE`), ban announced (`BANNED`), customer/admin ban, unban |
| `UserSecurityChanged` | `tokenVersion` incremented (`change`: `BANNED`, `BAN_ANNOUNCED`, `MERCHANT_BANNED`, `UNBANNED`, `PERMISSIONS_CHANGED`, `REMOVED`, `BANNED_BY_MERCHANT`, `BANNED_BY_ADMIN`, `PASSWORD_CHANGED`) |
| `AssistantChanged` | assistant `CREATED`, `PERMISSIONS_CHANGED`, `BANNED_BY_MERCHANT`, `BANNED_BY_ADMIN`, `UNBANNED`, `REMOVED` |

Payload (fields that do not apply are omitted; no email, NIC or names):

```json
{"eventId":"…","eventType":"UserStatusChanged","occurredAt":"2026-10-01T06:42:25Z","userId":"…","publicId":"USR-2610-7K2M9Q",
 "role":"ROLE_MERCHANT","status":"BAN_GRACE","previousStatus":"ACTIVE","storeId":"…","tokenVersion":1,
 "banEffectiveAt":"2026-10-15T06:42:25Z"}
```

Assistant events also carry `assistantStatus` and `permissions`; `UserSecurityChanged` and `AssistantChanged` carry
`change`. user-service consumes no topic; `processed_events` / `ProcessedEventStore` is ready for when it does.

## Mock ports

`ports.NotificationPort` (email/SMS) and `ports.VerificationPort` (email/phone verification) have mock adapters that
only log (with masked recipients) and always succeed, selected by `app.ports.notification` / `app.ports.verification`
(`mock`).

## Tests

```bash
mvn clean package        # Docker required (Testcontainers PostgreSQL, embedded Kafka)
```

- `AuthorizationMatrixTest`: every endpoint × anonymous and every role (incl. `ROLE_SERVICE`) → expected 200/201/204/401/403/404
- `LoginRulesTest`: sign-in per role and status, uniform errors, account/email/IP lockout, refresh rotation and reuse detection, logout, expiry, token-version revocation, forced password change, service tokens
- `MerchantLifecycleTest`: approve/reject/resubmit limits, the 14-day ban timeline with a fake clock, customer and admin bans, audit rows, admin search
- `AssistantManagementTest`: NIC uniqueness and release rules, store scoping (foreign ids → 404), permission changes revoking tokens
- `OutboxIntegrationTest`: event and change commit or roll back together; the relay publishes to Kafka; de-duplication
- `SuperAdminBootstrapTest`: exactly one super admin, idempotent (also concurrently), fails on an empty database without the env values
- `JwtServiceTest`, `PasswordHashingTest`, `CommonUtilitiesTest`, `UserFlowIntegrationTest`: claims, key/issuer/audience/alg checks, Argon2id/bcrypt, password policy, public ids, sanitizer, NIC, registration/profile/address flows
