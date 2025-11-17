package org.example.magiclink.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.dto.FormConfigDto;
import org.example.magiclink.dto.FormFieldDto;
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
     * Returns the form configuration for the magic link
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

        // Get token expiration info
        Long expiresIn = tokenService.getTokenExpiresIn(token);

        // Build form configuration
        FormConfigDto formConfig = FormConfigDto.builder()
            .email(email)
            .token(token)
            .title("Complete Your Profile")
            .description("Hi " + email + ", please complete your profile to continue.")
            .submitButtonText("Complete Setup")
            .tokenExpiresIn(expiresIn)
            .fields(buildFormFields())
            .build();

        return ResponseEntity.ok(formConfig);
    }

    /**
     * Build the form field definitions
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
