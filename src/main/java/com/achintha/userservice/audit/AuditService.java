package com.achintha.userservice.audit;

import com.achintha.userservice.common.Nic;
import com.achintha.userservice.security.Actor;
import com.achintha.userservice.user.AssistantPermission;
import com.achintha.userservice.user.User;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

/**
 * Writes audit rows for privileged mutations (admin, super admin, merchant owner, system), in the caller's
 * transaction so the row exists exactly when the change does. Snapshots never contain password hashes and mask NICs.
 */
@Service
@RequiredArgsConstructor
public class AuditService {

    public static final String TARGET_USER = "USER";
    public static final String TARGET_SERVICE_CLIENT = "SERVICE_CLIENT";

    private final AuditLogRepository repository;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    @Transactional(propagation = Propagation.MANDATORY)
    public void record(Actor actor, String action, String targetType, String targetId,
                       Map<String, Object> before, Map<String, Object> after, String reason) {
        AuditLogEntry entry = new AuditLogEntry();
        entry.setOccurredAt(clock.instant());
        entry.setActorId(actor.id());
        entry.setActorPublicId(actor.publicId() != null ? actor.publicId() : Actor.SYSTEM);
        entry.setActorRole(Actor.SYSTEM.equals(actor.publicId()) ? Actor.SYSTEM : actor.role().name());
        entry.setActorStoreId(actor.storeId());
        entry.setAction(action);
        entry.setTargetType(targetType);
        entry.setTargetId(targetId);
        entry.setBeforeState(before == null ? null : objectMapper.writeValueAsString(before));
        entry.setAfterState(after == null ? null : objectMapper.writeValueAsString(after));
        entry.setReason(reason);
        repository.save(entry);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void recordUserChange(Actor actor, String action, User target, Map<String, Object> before,
                                 String reason) {
        record(actor, action, TARGET_USER, target.getPublicId(), before, snapshot(target), reason);
    }

    /** Audit view of a user: security-relevant fields only, NIC masked, no password hash. */
    public static Map<String, Object> snapshot(User user) {
        Map<String, Object> state = new LinkedHashMap<>();
        state.put("publicId", user.getPublicId());
        state.put("email", user.getEmail());
        state.put("role", user.getRole());
        state.put("status", user.getStatus());
        if (user.getAssistantStatus() != null) {
            state.put("assistantStatus", user.getAssistantStatus());
            state.put("permissions", user.getPermissions().stream().map(AssistantPermission::name).sorted()
                    .toList());
        }
        if (user.getStoreId() != null) {
            state.put("storeId", user.getStoreId());
        }
        state.put("nic", Nic.mask(user.getNic()));
        state.put("tokenVersion", user.getTokenVersion());
        state.put("mustChangePassword", user.isMustChangePassword());
        if (user.getBanEffectiveAt() != null) {
            state.put("banEffectiveAt", user.getBanEffectiveAt());
        }
        if (user.getBanAnnouncedAt() != null) {
            state.put("banAnnouncedAt", user.getBanAnnouncedAt());
        }
        return state;
    }
}
