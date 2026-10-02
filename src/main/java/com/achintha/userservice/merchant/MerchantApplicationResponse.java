package com.achintha.userservice.merchant;

import com.achintha.userservice.user.User;
import com.achintha.userservice.user.UserStatus;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.List;

/** The merchant's view of their application: visible status and reason, attempts used and the latest submission. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record MerchantApplicationResponse(
        UserStatus status,
        String statusReason,
        int attemptsUsed,
        int maxAttempts,
        boolean canResubmit,
        int attemptNo,
        String businessName,
        List<String> documentKeys,
        Instant submittedAt,
        MerchantApplication.Decision decision,
        Instant decidedAt) {

    static MerchantApplicationResponse of(User merchant, MerchantApplication application, int maxAttempts) {
        boolean canResubmit = merchant.getStatus() == UserStatus.REJECTED
                && merchant.getApplicationAttempts() < maxAttempts;
        return new MerchantApplicationResponse(merchant.visibleStatus(), merchant.visibleStatusReason(),
                merchant.getApplicationAttempts(), maxAttempts, canResubmit, application.getAttemptNo(),
                application.getBusinessName(), List.copyOf(application.getDocumentKeys()),
                application.getSubmittedAt(), application.getDecision(), application.getDecidedAt());
    }
}
