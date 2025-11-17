package org.example.magiclink.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "form_submissions")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FormSubmissionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String submissionId;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String email;

    @Column
    private String phone;

    @Column
    private String additionalInfo;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private SubmissionStatus status;

    @Column
    private Boolean requiresMfa;

    @Column
    private LocalDateTime submittedAt;

    @Column
    private LocalDateTime processedAt;

    @PrePersist
    protected void onCreate() {
        submittedAt = LocalDateTime.now();
        requiresMfa = false;
        status = SubmissionStatus.PENDING;
    }

    public enum SubmissionStatus {
        PENDING,
        PROCESSING,
        MFA_REQUIRED,
        SUCCESS,
        FAILED
    }
}
