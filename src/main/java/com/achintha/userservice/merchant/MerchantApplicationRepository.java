package com.achintha.userservice.merchant;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MerchantApplicationRepository extends JpaRepository<MerchantApplication, UUID> {

    Optional<MerchantApplication> findFirstByUserIdOrderByAttemptNoDesc(UUID userId);

    List<MerchantApplication> findAllByUserIdOrderByAttemptNoAsc(UUID userId);
}
