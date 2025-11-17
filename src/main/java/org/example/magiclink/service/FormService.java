package org.example.magiclink.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.entity.FormSubmissionEntity;
import org.example.magiclink.repository.FormSubmissionRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Random;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class FormService {

    private final FormSubmissionRepository formSubmissionRepository;
    private final Random random = new Random();

    public FormSubmissionEntity createSubmission(String name, String email, String phone, String additionalInfo) {
        String submissionId = UUID.randomUUID().toString();

        FormSubmissionEntity submission = FormSubmissionEntity.builder()
                .submissionId(submissionId)
                .name(name)
                .email(email)
                .phone(phone)
                .additionalInfo(additionalInfo)
                .build();

        FormSubmissionEntity saved = formSubmissionRepository.save(submission);
        log.info("Created form submission with ID: {}", submissionId);

        // Simulate async processing
        processSubmissionAsync(saved);

        return saved;
    }

    public FormSubmissionEntity getSubmissionStatus(String submissionId) {
        return formSubmissionRepository.findBySubmissionId(submissionId)
                .orElseThrow(() -> new RuntimeException("Submission not found: " + submissionId));
    }

    private void processSubmissionAsync(FormSubmissionEntity submission) {
        // Simulate async processing in a new thread
        new Thread(() -> {
            try {
                // Update status to processing
                submission.setStatus(FormSubmissionEntity.SubmissionStatus.PROCESSING);
                formSubmissionRepository.save(submission);

                // Simulate processing delay (2-5 seconds)
                int delay = 2000 + random.nextInt(3000);
                Thread.sleep(delay);

                // Randomly determine outcome
                int outcome = random.nextInt(100);

                if (outcome < 20) {
                    // 20% chance - MFA required
                    submission.setStatus(FormSubmissionEntity.SubmissionStatus.MFA_REQUIRED);
                    submission.setRequiresMfa(true);
                    log.info("Submission {} requires MFA", submission.getSubmissionId());
                } else if (outcome < 85) {
                    // 65% chance - Success
                    submission.setStatus(FormSubmissionEntity.SubmissionStatus.SUCCESS);
                    log.info("Submission {} succeeded", submission.getSubmissionId());
                } else {
                    // 15% chance - Failed
                    submission.setStatus(FormSubmissionEntity.SubmissionStatus.FAILED);
                    log.info("Submission {} failed", submission.getSubmissionId());
                }

                submission.setProcessedAt(LocalDateTime.now());
                formSubmissionRepository.save(submission);

            } catch (InterruptedException e) {
                log.error("Error processing submission", e);
                submission.setStatus(FormSubmissionEntity.SubmissionStatus.FAILED);
                formSubmissionRepository.save(submission);
            }
        }).start();
    }
}
