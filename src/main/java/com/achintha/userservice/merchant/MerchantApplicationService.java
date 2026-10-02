package com.achintha.userservice.merchant;

import com.achintha.userservice.audit.AuditService;
import com.achintha.userservice.common.TextSanitizer;
import com.achintha.userservice.exception.ApiException;
import com.achintha.userservice.exception.ErrorCode;
import com.achintha.userservice.exception.NotFoundException;
import com.achintha.userservice.outbox.UserEventPublisher;
import com.achintha.userservice.ports.NotificationPort;
import com.achintha.userservice.security.Actor;
import com.achintha.userservice.user.Role;
import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserRepository;
import com.achintha.userservice.user.UserStatus;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Merchant onboarding (section 3.6): applications, admin approval/rejection and re-application after a rejection,
 * limited to {@code merchant.max-application-attempts} applications in total (registration included).
 */
@Service
public class MerchantApplicationService {

    private final MerchantApplicationRepository applications;
    private final UserRepository userRepository;
    private final UserEventPublisher events;
    private final AuditService audit;
    private final NotificationPort notifications;
    private final Clock clock;
    private final int maxAttempts;

    public MerchantApplicationService(MerchantApplicationRepository applications, UserRepository userRepository,
                                      UserEventPublisher events, AuditService audit, NotificationPort notifications,
                                      Clock clock,
                                      @Value("${merchant.max-application-attempts:3}") int maxAttempts) {
        this.applications = applications;
        this.userRepository = userRepository;
        this.events = events;
        this.audit = audit;
        this.notifications = notifications;
        this.clock = clock;
        this.maxAttempts = maxAttempts;
    }

    /** Stores an application and counts the attempt. */
    @Transactional(propagation = Propagation.MANDATORY)
    public MerchantApplication recordSubmission(User merchant, String businessName, List<String> documentKeys) {
        merchant.setApplicationAttempts(merchant.getApplicationAttempts() + 1);
        MerchantApplication application = new MerchantApplication();
        application.setId(UUID.randomUUID());
        application.setUserId(merchant.getId());
        application.setAttemptNo(merchant.getApplicationAttempts());
        application.setBusinessName(TextSanitizer.cleanLine(businessName));
        application.setDocumentKeys(documentKeys.stream().map(String::trim).toList());
        application.setSubmittedAt(clock.instant());
        return applications.save(application);
    }

    @Transactional(readOnly = true)
    public MerchantApplicationResponse view(Actor actor) {
        User merchant = merchant(actor);
        MerchantApplication latest = applications.findFirstByUserIdOrderByAttemptNoDesc(merchant.getId())
                .orElseThrow(() -> new NotFoundException("No application found"));
        return MerchantApplicationResponse.of(merchant, latest, maxAttempts);
    }

    /** A rejected merchant re-applies; the account returns to {@code PENDING_APPROVAL}. */
    @Transactional
    public MerchantApplicationResponse resubmit(Actor actor, String businessName, List<String> documentKeys) {
        User merchant = merchant(actor);
        if (merchant.getStatus() != UserStatus.REJECTED) {
            throw ApiException.invalidTransition("Only a rejected application can be resubmitted");
        }
        if (merchant.getApplicationAttempts() >= maxAttempts) {
            throw ApiException.conflict(ErrorCode.APPLICATION_LIMIT_REACHED,
                    "The maximum of " + maxAttempts + " applications has been reached");
        }
        Map<String, Object> before = AuditService.snapshot(merchant);
        MerchantApplication application = recordSubmission(merchant, businessName, documentKeys);
        UserStatus previous = merchant.getStatus();
        merchant.changeStatus(UserStatus.PENDING_APPROVAL, null, actor.publicId(), clock.instant());
        events.statusChanged(merchant, previous);
        audit.recordUserChange(actor, "MERCHANT_APPLICATION_RESUBMITTED", merchant, before, null);
        return MerchantApplicationResponse.of(merchant, application, maxAttempts);
    }

    @Transactional
    public void approve(Actor admin, String merchantPublicId, String note) {
        decide(admin, merchantPublicId, MerchantApplication.Decision.APPROVED, TextSanitizer.clean(note));
    }

    @Transactional
    public void reject(Actor admin, String merchantPublicId, String reason) {
        decide(admin, merchantPublicId, MerchantApplication.Decision.REJECTED, TextSanitizer.clean(reason));
    }

    private void decide(Actor admin, String merchantPublicId, MerchantApplication.Decision decision,
                        String reason) {
        User merchant = userRepository.findByPublicIdAndRole(merchantPublicId, Role.ROLE_MERCHANT)
                .orElseThrow(() -> new NotFoundException("Merchant not found"));
        if (merchant.getStatus() != UserStatus.PENDING_APPROVAL) {
            throw ApiException.invalidTransition("The merchant is not pending approval");
        }
        Instant now = clock.instant();
        Map<String, Object> before = AuditService.snapshot(merchant);
        MerchantApplication application = applications.findFirstByUserIdOrderByAttemptNoDesc(merchant.getId())
                .orElseThrow(() -> new NotFoundException("No application found"));
        application.setDecision(decision);
        application.setDecisionReason(reason);
        application.setDecidedBy(admin.publicId());
        application.setDecidedAt(now);

        UserStatus previous = merchant.getStatus();
        boolean approved = decision == MerchantApplication.Decision.APPROVED;
        merchant.changeStatus(approved ? UserStatus.ACTIVE : UserStatus.REJECTED, reason, admin.publicId(), now);
        events.statusChanged(merchant, previous);
        audit.recordUserChange(admin, approved ? "MERCHANT_APPROVED" : "MERCHANT_REJECTED", merchant, before,
                reason);
        notifications.notify(merchant.getEmail(), approved ? "MERCHANT_APPROVED" : "MERCHANT_REJECTED",
                approved ? "Your merchant application was approved" : "Your merchant application was rejected");
    }

    private User merchant(Actor actor) {
        return userRepository.findById(actor.id())
                .filter(User::isMerchant)
                .orElseThrow(() -> new NotFoundException("Merchant not found"));
    }
}
