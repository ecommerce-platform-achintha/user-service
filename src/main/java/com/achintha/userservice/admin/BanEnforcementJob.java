package com.achintha.userservice.admin;

import com.achintha.userservice.user.UserRepository;
import java.time.Clock;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.data.domain.PageRequest;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Every {@code app.scheduling.ban-enforcement.interval} (5 min): merchants in {@code BAN_GRACE} past
 * {@code banEffectiveAt} become {@code BANNED} (D4, section 3.2). One transaction per merchant, so one failure does
 * not block the others; an unban racing with the job loses or wins cleanly through optimistic locking.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BanEnforcementJob {

    private static final int BATCH_SIZE = 100;

    private final UserRepository userRepository;
    private final AccountStatusService accountStatusService;
    private final Clock clock;

    @Scheduled(fixedDelayString = "${app.scheduling.ban-enforcement.interval:PT5M}")
    @SchedulerLock(name = "user-service.banEnforcement", lockAtMostFor = "PT10M")
    public void scheduledRun() {
        run();
    }

    /** @return the number of bans enforced */
    public int run() {
        int enforced = 0;
        List<UUID> due;
        do {
            due = userRepository.findMerchantsDueForBan(clock.instant(), PageRequest.of(0, BATCH_SIZE));
            int enforcedInBatch = 0;
            for (UUID merchantId : due) {
                try {
                    if (accountStatusService.enforceMerchantBan(merchantId)) {
                        enforcedInBatch++;
                    }
                } catch (ObjectOptimisticLockingFailureException e) {
                    log.info("Merchant {} changed concurrently; ban enforcement retried on the next run", merchantId);
                } catch (RuntimeException e) {
                    log.error("Could not enforce the ban of merchant {}", merchantId, e);
                }
            }
            enforced += enforcedInBatch;
            if (enforcedInBatch == 0) {
                break; // only failures left in this batch: retry on the next run instead of looping
            }
        } while (due.size() == BATCH_SIZE);
        if (enforced > 0) {
            log.info("Enforced {} merchant ban(s)", enforced);
        }
        return enforced;
    }
}
