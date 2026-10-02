package com.achintha.userservice.user;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

/**
 * An account. Never bound to requests or serialized: controllers use request/response DTOs only.
 *
 * <p>No @ToString/@Data on purpose: keeps the password hash and NIC out of logs and avoids lazy-loading surprises.
 */
@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
public class User {

    @Id
    private UUID id;

    @Column(name = "public_id", nullable = false, unique = true, length = 20)
    private String publicId;

    /** Stored lower-cased; unique case-insensitively ({@code ux_users_email}). */
    @Column(nullable = false, length = 254)
    private String email;

    /** {@code {argon2}...} (or legacy {@code {bcrypt}...}) hash, never the raw password. */
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "first_name", nullable = false, length = 100)
    private String firstName;

    @Column(name = "last_name", nullable = false, length = 100)
    private String lastName;

    /** Upper-cased; not unique in general (D3), unique among NIC-holding assistants. */
    @Column(length = 12)
    private String nic;

    @Column(length = 16)
    private String phone;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private Role role;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private UserStatus status;

    /** Assistants only. */
    @Enumerated(EnumType.STRING)
    @Column(name = "assistant_status", length = 32)
    private AssistantStatus assistantStatus;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "assistant_permissions", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "permission", nullable = false, length = 32)
    private Set<AssistantPermission> permissions = new HashSet<>();

    @Column(name = "status_reason", length = 500)
    private String statusReason;

    /** publicId of the actor, or {@code SYSTEM} for the scheduler and bootstrap. */
    @Column(name = "status_changed_by", length = 40)
    private String statusChangedBy;

    @Column(name = "status_changed_at")
    private Instant statusChangedAt;

    /** Merchant ban: when BAN_GRACE turns into BANNED. */
    @Column(name = "ban_effective_at")
    private Instant banEffectiveAt;

    /** When the ban (and its reason) became visible to the user. */
    @Column(name = "ban_announced_at")
    private Instant banAnnouncedAt;

    @Column(name = "must_change_password", nullable = false)
    private boolean mustChangePassword;

    /** Incremented on every security-relevant change; tokens carrying an older {@code tv} are rejected. */
    @Column(name = "token_version", nullable = false)
    private long tokenVersion;

    /** Merchant: own store, fixed at registration. Assistant: the employing merchant's store. */
    @Column(name = "store_id")
    private UUID storeId;

    @Column(name = "failed_login_count", nullable = false)
    private int failedLoginCount;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    /** Merchant applications submitted so far (registration counts as the first). */
    @Column(name = "application_attempts", nullable = false)
    private int applicationAttempts;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /** Wrapper type on purpose: {@code null} marks a new entity, so save() persists it instead of merging a copy. */
    @Version
    @Column(nullable = false)
    private Long version;

    public boolean isAssistant() {
        return role == Role.ROLE_ASSISTANT;
    }

    public boolean isMerchant() {
        return role == Role.ROLE_MERCHANT;
    }

    /** Records a status change with its reason, actor and time (section 3.1). */
    public void changeStatus(UserStatus newStatus, String reason, String actorPublicId, Instant now) {
        this.status = newStatus;
        this.statusReason = reason;
        this.statusChangedBy = actorPublicId;
        this.statusChangedAt = now;
    }

    public void changeAssistantStatus(AssistantStatus newStatus, String reason, String actorPublicId, Instant now) {
        this.assistantStatus = newStatus;
        this.statusReason = reason;
        this.statusChangedBy = actorPublicId;
        this.statusChangedAt = now;
    }

    public void incrementTokenVersion() {
        this.tokenVersion++;
    }

    /** Assistant permissions; a merchant implicitly holds all of them (never stored). */
    public Set<AssistantPermission> effectivePermissions() {
        if (role == Role.ROLE_MERCHANT) {
            return EnumSet.allOf(AssistantPermission.class);
        }
        return permissions.isEmpty() ? EnumSet.noneOf(AssistantPermission.class) : EnumSet.copyOf(permissions);
    }

    /**
     * Status as the user may see it: the silent merchant ban grace period looks like {@code ACTIVE} (D4, section
     * 3.2). Used in login and {@code /me} responses and in the access token.
     */
    public UserStatus visibleStatus() {
        return status == UserStatus.BAN_GRACE ? UserStatus.ACTIVE : status;
    }

    /**
     * The reason shown to the user, only once it is meant to be visible: rejected merchants, banned customers and
     * admins, announced merchant bans, banned or removed assistants. Never during {@code BAN_GRACE}.
     */
    public String visibleStatusReason() {
        if (role == Role.ROLE_ASSISTANT) {
            return assistantStatus != null && assistantStatus != AssistantStatus.ACTIVE ? statusReason : null;
        }
        return switch (status) {
            case REJECTED -> statusReason;
            case BANNED -> role != Role.ROLE_MERCHANT || banAnnouncedAt != null ? statusReason : null;
            default -> null;
        };
    }
}
