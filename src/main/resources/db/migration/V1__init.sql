-- user-service baseline schema (docs/marketplace-design.md, sections 1, 3 and 9).
-- Replaces the tables Hibernate used to create (the dev database is reset once, D18).
-- From now on every change is a new V<n>__*.sql script; this file is never edited after release.

-- ---------------------------------------------------------------------------------------------------------------
-- Users: one role per account, status machine, assistant sub-status, lockout and token version
-- ---------------------------------------------------------------------------------------------------------------
CREATE TABLE users (
    id                   uuid         PRIMARY KEY,
    public_id            varchar(20)  NOT NULL,
    email                varchar(254) NOT NULL,
    password_hash        varchar(255) NOT NULL,
    first_name           varchar(100) NOT NULL,
    last_name            varchar(100) NOT NULL,
    nic                  varchar(12),
    phone                varchar(16),
    role                 varchar(32)  NOT NULL,
    status               varchar(32)  NOT NULL,
    assistant_status     varchar(32),
    status_reason        varchar(500),
    status_changed_by    varchar(40),
    status_changed_at    timestamptz,
    ban_effective_at     timestamptz,
    ban_announced_at     timestamptz,
    must_change_password boolean      NOT NULL DEFAULT false,
    token_version        bigint       NOT NULL DEFAULT 0,
    store_id             uuid,
    failed_login_count   integer      NOT NULL DEFAULT 0,
    locked_until         timestamptz,
    application_attempts integer      NOT NULL DEFAULT 0,
    created_at           timestamptz  NOT NULL,
    updated_at           timestamptz  NOT NULL,
    version              bigint       NOT NULL DEFAULT 0,

    CONSTRAINT ux_users_public_id UNIQUE (public_id),
    -- ROLE_SERVICE exists only inside service tokens, never on a stored account
    CONSTRAINT ck_users_role CHECK (role IN ('ROLE_CUSTOMER', 'ROLE_MERCHANT', 'ROLE_ASSISTANT', 'ROLE_ADMIN',
                                             'ROLE_SUPER_ADMIN')),
    CONSTRAINT ck_users_status CHECK (status IN ('ACTIVE', 'PENDING_APPROVAL', 'REJECTED', 'BAN_GRACE', 'BANNED')),
    -- Approval states and the silent grace period exist for merchants only
    CONSTRAINT ck_users_merchant_only_status CHECK (
        role = 'ROLE_MERCHANT' OR status IN ('ACTIVE', 'BANNED')),
    CONSTRAINT ck_users_assistant_status CHECK (
        (role = 'ROLE_ASSISTANT' AND assistant_status IN ('ACTIVE', 'BANNED_BY_MERCHANT', 'BANNED_BY_ADMIN', 'REMOVED'))
        OR (role <> 'ROLE_ASSISTANT' AND assistant_status IS NULL)),
    CONSTRAINT ck_users_store_id CHECK (
        (role IN ('ROLE_MERCHANT', 'ROLE_ASSISTANT')) = (store_id IS NOT NULL)),
    -- Phone is mandatory for customers, merchants and assistants (section 13, point 7)
    CONSTRAINT ck_users_phone CHECK (
        role NOT IN ('ROLE_CUSTOMER', 'ROLE_MERCHANT', 'ROLE_ASSISTANT') OR phone IS NOT NULL),
    -- Old (9 digits + V/X) or new (12 digits) NIC, stored upper-case
    CONSTRAINT ck_users_nic CHECK (nic IS NULL OR nic ~ '^([0-9]{9}[VX]|[0-9]{12})$')
);

-- Email is unique per user, case-insensitively (D3). The application also stores it lower-cased.
CREATE UNIQUE INDEX ux_users_email ON users (lower(email));
-- Exactly one super admin (section 3.5)
CREATE UNIQUE INDEX ux_users_single_super_admin ON users (role) WHERE role = 'ROLE_SUPER_ADMIN';
-- An assistant's NIC belongs to one store at a time. It is released when the merchant removes or bans the
-- assistant; an assistant banned by an admin keeps blocking it permanently (section 13, point 5).
CREATE UNIQUE INDEX ux_users_assistant_nic ON users (nic)
    WHERE role = 'ROLE_ASSISTANT' AND assistant_status IN ('ACTIVE', 'BANNED_BY_ADMIN');
-- 1 merchant = 1 store
CREATE UNIQUE INDEX ux_users_merchant_store ON users (store_id) WHERE role = 'ROLE_MERCHANT';
CREATE INDEX idx_users_store_id ON users (store_id) WHERE store_id IS NOT NULL;
CREATE INDEX idx_users_role_status ON users (role, status);
-- Ban enforcement scheduler
CREATE INDEX idx_users_ban_grace ON users (ban_effective_at) WHERE status = 'BAN_GRACE';

CREATE TABLE assistant_permissions (
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    permission varchar(32) NOT NULL,
    PRIMARY KEY (user_id, permission),
    CONSTRAINT ck_assistant_permissions CHECK (permission IN ('ORDER_VIEW', 'ORDER_QUOTE', 'PAYMENT_VERIFY',
        'ORDER_SHIP', 'PRODUCT_EDIT', 'STOCK_EDIT', 'DISCOUNT_MANAGE', 'CUSTOMER_BLOCK', 'REVIEW_REPLY'))
);

-- ---------------------------------------------------------------------------------------------------------------
-- Merchant applications: one row per submission (registration = attempt 1, then each resubmission)
-- ---------------------------------------------------------------------------------------------------------------
CREATE TABLE merchant_applications (
    id              uuid         PRIMARY KEY,
    user_id         uuid         NOT NULL REFERENCES users (id),
    attempt_no      integer      NOT NULL,
    business_name   varchar(150) NOT NULL,
    submitted_at    timestamptz  NOT NULL,
    decision        varchar(16),
    decision_reason varchar(500),
    decided_by      varchar(40),
    decided_at      timestamptz,
    CONSTRAINT ux_merchant_applications_attempt UNIQUE (user_id, attempt_no),
    CONSTRAINT ck_merchant_applications_decision CHECK (decision IS NULL OR decision IN ('APPROVED', 'REJECTED'))
);

-- Document storage keys (mock: no file storage yet)
CREATE TABLE merchant_application_documents (
    application_id uuid         NOT NULL REFERENCES merchant_applications (id) ON DELETE CASCADE,
    position       integer      NOT NULL,
    document_key   varchar(200) NOT NULL,
    PRIMARY KEY (application_id, position)
);

-- ---------------------------------------------------------------------------------------------------------------
-- Addresses (scoped by the owning user)
-- ---------------------------------------------------------------------------------------------------------------
CREATE TABLE addresses (
    id             uuid         PRIMARY KEY,
    public_id      varchar(20)  NOT NULL,
    user_id        uuid         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    recipient_name varchar(150) NOT NULL,
    phone          varchar(16)  NOT NULL,
    line1          varchar(200) NOT NULL,
    line2          varchar(200),
    city           varchar(100) NOT NULL,
    district       varchar(50)  NOT NULL,
    postal_code    varchar(20)  NOT NULL,
    country        varchar(100) NOT NULL,
    created_at     timestamptz  NOT NULL,
    updated_at     timestamptz  NOT NULL,
    version        bigint       NOT NULL DEFAULT 0,
    CONSTRAINT ux_addresses_public_id UNIQUE (public_id)
);
CREATE INDEX idx_addresses_user_id ON addresses (user_id);

-- ---------------------------------------------------------------------------------------------------------------
-- Refresh tokens: opaque, stored as SHA-256 hashes, rotated on every use, reuse revokes the family
-- ---------------------------------------------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    id            uuid        PRIMARY KEY,
    user_id       uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash    varchar(64) NOT NULL,
    family_id     uuid        NOT NULL,
    rotated_from  uuid,
    issued_at     timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    revoked_at    timestamptz,
    revoke_reason varchar(40),
    CONSTRAINT ux_refresh_tokens_hash UNIQUE (token_hash)
);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------------------------------------------
-- Login throttle per client IP and per unknown email (known accounts use users.failed_login_count/locked_until)
-- ---------------------------------------------------------------------------------------------------------------
CREATE TABLE login_throttle (
    throttle_key      varchar(300) PRIMARY KEY,
    failed_count      integer      NOT NULL,
    window_started_at timestamptz  NOT NULL,
    locked_until      timestamptz,
    updated_at        timestamptz  NOT NULL
);

-- ---------------------------------------------------------------------------------------------------------------
-- Service clients allowed to request ROLE_SERVICE tokens. Secrets stay in Config Server / secret store; this table
-- only registers the clients (synced at startup) so one can be disabled without a redeploy.
-- ---------------------------------------------------------------------------------------------------------------
CREATE TABLE service_clients (
    client_id            varchar(64) PRIMARY KEY,
    enabled              boolean     NOT NULL DEFAULT true,
    created_at           timestamptz NOT NULL,
    last_token_issued_at timestamptz
);

-- ---------------------------------------------------------------------------------------------------------------
-- Append-only audit log of privileged mutations (section 1). Sensitive fields are masked before insert.
-- ---------------------------------------------------------------------------------------------------------------
CREATE TABLE audit_log (
    id              bigserial    PRIMARY KEY,
    occurred_at     timestamptz  NOT NULL,
    actor_id        uuid,
    actor_public_id varchar(40)  NOT NULL,
    actor_role      varchar(32)  NOT NULL,
    actor_store_id  uuid,
    action          varchar(64)  NOT NULL,
    target_type     varchar(32)  NOT NULL,
    target_id       varchar(64)  NOT NULL,
    before_state    text,
    after_state     text,
    reason          varchar(500)
);
CREATE INDEX idx_audit_log_target ON audit_log (target_type, target_id);
CREATE INDEX idx_audit_log_occurred_at ON audit_log (occurred_at);

CREATE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- ---------------------------------------------------------------------------------------------------------------
-- Transactional outbox (section 9) and consumer de-duplication
-- ---------------------------------------------------------------------------------------------------------------
CREATE TABLE outbox (
    id           bigserial     PRIMARY KEY,
    event_id     uuid          NOT NULL,
    aggregate_id uuid          NOT NULL,
    event_type   varchar(64)   NOT NULL,
    topic        varchar(100)  NOT NULL,
    msg_key      varchar(100)  NOT NULL,
    payload      text          NOT NULL,
    created_at   timestamptz   NOT NULL,
    published_at timestamptz,
    attempts     integer       NOT NULL DEFAULT 0,
    last_error   varchar(1000),
    CONSTRAINT ux_outbox_event_id UNIQUE (event_id)
);
CREATE INDEX idx_outbox_unpublished ON outbox (id) WHERE published_at IS NULL;

CREATE TABLE processed_events (
    event_id     uuid         NOT NULL,
    consumer     varchar(100) NOT NULL,
    processed_at timestamptz  NOT NULL,
    PRIMARY KEY (event_id, consumer)
);

-- ---------------------------------------------------------------------------------------------------------------
-- ShedLock (JdbcTemplateLockProvider, usingDbTime)
-- ---------------------------------------------------------------------------------------------------------------
CREATE TABLE shedlock (
    name       varchar(64)  PRIMARY KEY,
    lock_until timestamptz  NOT NULL,
    locked_at  timestamptz  NOT NULL,
    locked_by  varchar(255) NOT NULL
);
