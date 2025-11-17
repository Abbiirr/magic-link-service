package org.example.magiclink.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.dto.FormConfigDto;
import org.example.magiclink.dto.FormFieldDto;
import org.example.magiclink.dto.PageConfigDto;
import org.example.magiclink.entity.FormProcessingStatus;
import org.example.magiclink.service.FormProcessingService;
import org.example.magiclink.service.TokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@Slf4j
@RestController
@RequestMapping("/api/magic-link")
@RequiredArgsConstructor
public class MagicLinkApiController {

    private final TokenService tokenService;
    private final FormProcessingService formProcessingService;

    /**
     * GET /api/magic-link/form?token=xxx
     * Returns the form configuration for the magic link (multi-page)
     */
    @GetMapping("/form")
    public ResponseEntity<?> getFormConfig(@RequestParam String token) {
        log.info("GET /api/magic-link/form called with token: {}", token);

        // Validate token
        Optional<String> emailOpt = tokenService.validateToken(token);
        if (emailOpt.isEmpty()) {
            log.warn("Invalid or expired token: {}", token);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", "Invalid or expired token");
            error.put("code", "INVALID_TOKEN");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }

        String email = emailOpt.get();
        log.info("Token validated for email: {}", email);

        // Get or create processing status
        FormProcessingStatus processingStatus = formProcessingService.getOrCreateStatus(token, email);

        // Get token expiration info
        Long expiresIn = tokenService.getTokenExpiresIn(token);

        // Build multi-page form configuration
        FormConfigDto formConfig = FormConfigDto.builder()
            .email(email)
            .token(token)
            .title("Registration Flow")
            .description("Welcome! Complete your registration in a few simple steps.")
            .tokenExpiresIn(expiresIn)
            .multiPage(true)
            .currentPage(processingStatus.getCurrentPage())
            .pages(buildPages(email))
            .build();

        return ResponseEntity.ok(formConfig);
    }

    /**
     * Build multi-page configuration
     */
    private List<PageConfigDto> buildPages(String email) {
        List<PageConfigDto> pages = new ArrayList<>();

        // Page 0: Prompt/Welcome page
        pages.add(PageConfigDto.builder()
            .pageNumber(0)
            .pageType("prompt")
            .title("Welcome to Our Platform!")
            .description("We're excited to have you here. Would you like to complete your registration?")
            .buttonText("Yes, Register")
            .nextAction("navigate")
            .build());

        // Page 1: Registration form
        pages.add(PageConfigDto.builder()
            .pageNumber(1)
            .pageType("form")
            .title("Complete Your Profile")
            .description("Please provide the following information to complete your registration.")
            .buttonText("Submit Registration")
            .fields(buildFormFields())
            .nextAction("submit")
            .build());

        // Page 2: Loading page
        pages.add(PageConfigDto.builder()
            .pageNumber(2)
            .pageType("loading")
            .title("Processing Your Registration")
            .description("Please wait while we process your information...")
            .nextAction("poll")
            .build());

        // Page 3: MFA Code page (conditional)
        pages.add(PageConfigDto.builder()
            .pageNumber(3)
            .pageType("mfa")
            .title("Verify Your Identity")
            .description("Please enter the verification code to complete your registration.")
            .buttonText("Verify Code")
            .fields(buildMfaFields())
            .nextAction("submit")
            .build());

        // Page 4: Success page
        pages.add(PageConfigDto.builder()
            .pageNumber(4)
            .pageType("success")
            .title("Registration Successful!")
            .description("Your account has been created successfully. Redirecting you to the dashboard...")
            .nextAction("navigate")
            .build());

        // Page 5: Error page
        pages.add(PageConfigDto.builder()
            .pageNumber(5)
            .pageType("error")
            .title("Registration Failed")
            .description("We encountered an error during registration. Please try again.")
            .buttonText("Try Again")
            .nextAction("navigate")
            .build());

        return pages;
    }

    /**
     * Build the registration form field definitions
     */
    private List<FormFieldDto> buildFormFields() {
        List<FormFieldDto> fields = new ArrayList<>();

        // Full Name field
        fields.add(FormFieldDto.builder()
            .name("name")
            .label("Full Name")
            .type("text")
            .required(true)
            .placeholder("Enter your full name")
            .build());

        // Company field
        fields.add(FormFieldDto.builder()
            .name("company")
            .label("Company")
            .type("text")
            .required(false)
            .placeholder("Enter your company name (optional)")
            .build());

        // Role field with options
        List<FormFieldDto.FormFieldOption> roleOptions = Arrays.asList(
            FormFieldDto.FormFieldOption.builder()
                .value("")
                .label("Select your role (optional)")
                .build(),
            FormFieldDto.FormFieldOption.builder()
                .value("developer")
                .label("Developer")
                .build(),
            FormFieldDto.FormFieldOption.builder()
                .value("designer")
                .label("Designer")
                .build(),
            FormFieldDto.FormFieldOption.builder()
                .value("manager")
                .label("Manager")
                .build(),
            FormFieldDto.FormFieldOption.builder()
                .value("other")
                .label("Other")
                .build()
        );

        fields.add(FormFieldDto.builder()
            .name("role")
            .label("Role")
            .type("select")
            .required(false)
            .options(roleOptions)
            .build());

        return fields;
    }

    /**
     * Build MFA code field
     */
    private List<FormFieldDto> buildMfaFields() {
        List<FormFieldDto> fields = new ArrayList<>();

        fields.add(FormFieldDto.builder()
            .name("mfaCode")
            .label("Verification Code")
            .type("text")
            .required(true)
            .placeholder("Enter 6-digit code")
            .build());

        return fields;
    }

    /**
     * POST /api/magic-link/submit-page?token=xxx
     * Submit data for the current page and navigate to next
     */
    @PostMapping("/submit-page")
    public ResponseEntity<Map<String, Object>> submitPage(
            @RequestParam String token,
            @RequestParam Integer pageNumber,
            @RequestBody Map<String, String> pageData) {

        log.info("POST /api/magic-link/submit-page called with token: {}, page: {}", token, pageNumber);

        // Validate the magic link token
        Optional<String> emailOpt = tokenService.validateToken(token);
        if (emailOpt.isEmpty()) {
            log.warn("Invalid or expired token: {}", token);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", "Invalid or expired token");
            error.put("code", "INVALID_TOKEN");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }

        String email = emailOpt.get();
        log.info("Page {} data received for email: {}", pageNumber, email);

        // Process the page submission
        String nextPage = formProcessingService.submitPage(token, pageNumber, pageData);

        // Return success with next page
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("nextPage", nextPage);
        response.put("message", "Page submitted successfully");
        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/magic-link/next-page?token=xxx
     * Get the next page to display (used after loading page)
     */
    @GetMapping("/next-page")
    public ResponseEntity<Map<String, Object>> getNextPage(@RequestParam String token) {
        log.debug("GET /api/magic-link/next-page called with token: {}", token);

        Optional<FormProcessingStatus> statusOpt = formProcessingService.getStatus(token);
        if (statusOpt.isEmpty()) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", "Processing status not found");
            error.put("code", "STATUS_NOT_FOUND");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }

        FormProcessingStatus status = statusOpt.get();
        Map<String, Object> response = new HashMap<>();

        if (status.getStatus() == FormProcessingStatus.ProcessingStatus.COMPLETED) {
            // Determine next page based on MFA requirement
            if (Boolean.TRUE.equals(status.getMfaRequired())) {
                response.put("nextPage", "mfa"); // Page 3
                response.put("pageNumber", 3);
            } else {
                response.put("nextPage", "success"); // Page 4
                response.put("pageNumber", 4);
            }
            response.put("status", "ready");
            response.put("message", "Ready to navigate to next page");
        } else if (status.getStatus() == FormProcessingStatus.ProcessingStatus.FAILED) {
            response.put("nextPage", "error"); // Page 5
            response.put("pageNumber", 5);
            response.put("status", "failed");
            response.put("message", status.getErrorMessage());
        } else {
            response.put("status", "processing");
            response.put("progress", status.getProgress());
            response.put("message", "Still processing");
        }

        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/magic-link/process-form?token=xxx
     * Process the submitted form data (already exists in AuthController, but adding here for API consistency)
     */
    @PostMapping("/process-form")
    public ResponseEntity<Map<String, Object>> processFormData(
            @RequestParam String token,
            @RequestBody Map<String, String> formData) {

        log.info("POST /api/magic-link/process-form called with token: {}", token);

        // Validate the magic link token
        Optional<String> emailOpt = tokenService.validateToken(token);
        if (emailOpt.isEmpty()) {
            log.warn("Invalid or expired token: {}", token);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", "Invalid or expired token");
            error.put("code", "INVALID_TOKEN");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }

        String email = emailOpt.get();
        log.info("Form data received for email: {}", email);

        // Start background processing
        formProcessingService.processFormDataAsync(token, formData);

        // Return success with next step
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "Form data received, processing in background");
        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/magic-link/check-status?token=xxx
     * Check the processing status (already exists in AuthController, but adding here for API consistency)
     */
    @GetMapping("/check-status")
    public ResponseEntity<Map<String, Object>> checkProcessingStatus(@RequestParam String token) {
        log.debug("GET /api/magic-link/check-status called with token: {}", token);

        Optional<FormProcessingStatus> statusOpt = formProcessingService.getStatus(token);
        if (statusOpt.isEmpty()) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", "Processing status not found");
            error.put("code", "STATUS_NOT_FOUND");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }

        FormProcessingStatus status = statusOpt.get();
        Map<String, Object> response = new HashMap<>();

        if (status.getStatus() == FormProcessingStatus.ProcessingStatus.COMPLETED) {
            response.put("status", "completed");
            response.put("progress", 100);
            response.put("nextStep", "/");
            response.put("message", "Processing completed successfully");
        } else if (status.getStatus() == FormProcessingStatus.ProcessingStatus.FAILED) {
            response.put("status", "failed");
            response.put("message", status.getErrorMessage());
            response.put("code", "PROCESSING_FAILED");
        } else {
            response.put("status", "processing");
            response.put("progress", status.getProgress());
            response.put("message", "Processing in progress");
        }

        return ResponseEntity.ok(response);
    }
}
