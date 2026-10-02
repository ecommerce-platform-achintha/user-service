package com.achintha.userservice.user;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, UUID>, JpaSpecificationExecutor<User> {

    /** Callers pass the lower-cased email (emails are stored lower-cased). */
    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    boolean existsByPublicId(String publicId);

    Optional<User> findByPublicId(String publicId);

    Optional<User> findByPublicIdAndRole(String publicId, Role role);

    /** Owner-side assistant lookup, always scoped by the caller's store (BOLA). */
    Optional<User> findByPublicIdAndRoleAndStoreId(String publicId, Role role, UUID storeId);

    Page<User> findAllByRoleAndStoreId(Role role, UUID storeId, Pageable pageable);

    List<User> findAllByRoleAndStoreId(Role role, UUID storeId);

    Optional<User> findByRoleAndStoreId(Role role, UUID storeId);

    Page<User> findAllByRoleAndStatus(Role role, UserStatus status, Pageable pageable);

    Page<User> findAllByRole(Role role, Pageable pageable);

    boolean existsByRole(Role role);

    boolean existsByRoleAndNicAndAssistantStatusIn(Role role, String nic, Collection<AssistantStatus> statuses);

    /** Light per-request lookup for {@code UserSecurityStateFilter}. */
    @Query("select new com.achintha.userservice.user.SecuritySnapshot(u.tokenVersion, u.mustChangePassword) "
            + "from User u where u.id = :id")
    Optional<SecuritySnapshot> findSecuritySnapshot(@Param("id") UUID id);

    /** Merchants whose silent grace period is over (ban enforcement scheduler). */
    @Query("""
            select u.id from User u
            where u.role = com.achintha.userservice.user.Role.ROLE_MERCHANT
              and u.status = com.achintha.userservice.user.UserStatus.BAN_GRACE
              and u.banEffectiveAt <= :now
            order by u.banEffectiveAt
            """)
    List<UUID> findMerchantsDueForBan(@Param("now") Instant now, Pageable pageable);
}
