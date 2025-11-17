package org.example.magiclink.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.entity.FormProcessingStatus;
import org.example.magiclink.entity.User;
import org.example.magiclink.repository.FormProcessingRepository;
import org.example.magiclink.repository.UserRepository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class FormProcessingService {

    private final FormProcessingRepository processingRepository;
    private final UserRepository userRepository;

    /**
     * Create a new processing status entry for a token
     */
    public FormProcessingStatus createProcessingStatus(String token, String email) {
        FormProcessingStatus status = new FormProcessingStatus();
        status.setToken(token);
        status.setEmail(email);
        status.setStatus(FormProcessingStatus.ProcessingStatus.PENDING);
        status.setProgress(0);
        return processingRepository.save(status);
    }

    /**
     * Start processing form data in the background
     */
    @Async
    @Transactional
    public void processFormDataAsync(String token, Map<String, String> formData) {
        log.info("Starting background processing for token: {}", token);

        Optional<FormProcessingStatus> statusOpt = processingRepository.findByToken(token);
        if (statusOpt.isEmpty()) {
            log.error("Processing status not found for token: {}", token);
            return;
        }

        FormProcessingStatus status = statusOpt.get();
        status.setStatus(FormProcessingStatus.ProcessingStatus.PROCESSING);
        status.setFormData(formData);
        status.setProgress(10);
        processingRepository.save(status);

        try {
            // Simulate business logic processing
            // Step 1: Validate form data
            log.info("Step 1: Validating form data for {}", status.getEmail());
            Thread.sleep(1000); // Simulate processing time
            status.setProgress(30);
            processingRepository.save(status);

            // Step 2: Update user profile
            log.info("Step 2: Updating user profile for {}", status.getEmail());
            updateUserProfile(status.getEmail(), formData);
            Thread.sleep(1000);
            status.setProgress(60);
            processingRepository.save(status);

            // Step 3: Send welcome email or perform additional setup
            log.info("Step 3: Performing additional setup for {}", status.getEmail());
            performAdditionalSetup(status.getEmail(), formData);
            Thread.sleep(1000);
            status.setProgress(90);
            processingRepository.save(status);

            // Step 4: Finalize
            log.info("Step 4: Finalizing setup for {}", status.getEmail());
            Thread.sleep(500);
            status.setProgress(100);
            status.setStatus(FormProcessingStatus.ProcessingStatus.COMPLETED);
            status.setCompletedAt(LocalDateTime.now());
            processingRepository.save(status);

            log.info("Successfully completed processing for token: {}", token);

        } catch (Exception e) {
            log.error("Error processing form data for token: {}", token, e);
            status.setStatus(FormProcessingStatus.ProcessingStatus.FAILED);
            status.setErrorMessage(e.getMessage());
            status.setCompletedAt(LocalDateTime.now());
            processingRepository.save(status);
        }
    }

    /**
     * Update user profile with form data
     */
    private void updateUserProfile(String email, Map<String, String> formData) {
        userRepository.findByEmail(email).ifPresent(user -> {
            // Store any additional user data from the form
            // For now, we'll just update the last login time
            user.setLastLoginAt(LocalDateTime.now());
            user.setEmailVerified(true);
            userRepository.save(user);

            log.info("Updated user profile for: {}", email);
            log.info("Form data received: name={}, company={}",
                formData.get("name"), formData.get("company"));
        });
    }

    /**
     * Perform additional setup tasks
     */
    private void performAdditionalSetup(String email, Map<String, String> formData) {
        // Add any additional business logic here:
        // - Send welcome email
        // - Create default resources
        // - Set up user workspace
        // - Initialize user preferences
        // - Log analytics events
        // etc.

        log.info("Performing additional setup for user: {}", email);
        log.info("Additional setup data: {}", formData);
    }

    /**
     * Get processing status for a token
     */
    public Optional<FormProcessingStatus> getStatus(String token) {
        return processingRepository.findByToken(token);
    }

    /**
     * Check if processing is complete
     */
    public boolean isProcessingComplete(String token) {
        return processingRepository.findByToken(token)
            .map(status -> status.getStatus() == FormProcessingStatus.ProcessingStatus.COMPLETED)
            .orElse(false);
    }
}
