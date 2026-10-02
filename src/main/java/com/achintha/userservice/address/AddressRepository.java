package com.achintha.userservice.address;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

/** Every lookup is scoped by the owning user's id. */
public interface AddressRepository extends JpaRepository<Address, UUID> {

    Page<Address> findAllByUserId(UUID userId, Pageable pageable);

    Optional<Address> findByPublicIdAndUserId(String publicId, UUID userId);

    long countByUserId(UUID userId);

    boolean existsByPublicId(String publicId);
}
