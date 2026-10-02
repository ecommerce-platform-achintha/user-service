package com.achintha.userservice.merchant;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OrderColumn;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** One merchant application (registration = attempt 1, then each resubmission after a rejection). */
@Entity
@Table(name = "merchant_applications")
@Getter
@Setter
@NoArgsConstructor
public class MerchantApplication {

    public enum Decision { APPROVED, REJECTED }

    @Id
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "attempt_no", nullable = false)
    private int attemptNo;

    @Column(name = "business_name", nullable = false, length = 150)
    private String businessName;

    /** Keys of the (mock) document storage. */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "merchant_application_documents", joinColumns = @JoinColumn(name = "application_id"))
    @OrderColumn(name = "position")
    @Column(name = "document_key", nullable = false, length = 200)
    private List<String> documentKeys = new ArrayList<>();

    @Column(name = "submitted_at", nullable = false)
    private Instant submittedAt;

    @Enumerated(EnumType.STRING)
    @Column(length = 16)
    private Decision decision;

    @Column(name = "decision_reason", length = 500)
    private String decisionReason;

    @Column(name = "decided_by", length = 40)
    private String decidedBy;

    @Column(name = "decided_at")
    private Instant decidedAt;
}
