package org.example.magiclink.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.entity.FormSubmissionEntity;
import org.example.magiclink.service.FormService;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/form")
@RequiredArgsConstructor
@Slf4j
public class FormController {

    private final FormService formService;

    /**
     * API 1: Get the form (unauthenticated) - Initial landing page
     */
    @GetMapping
    public String getForm(Model model) {
        log.info("Form requested");
        return "form-start";
    }

    /**
     * Page 2: Registration form page
     */
    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        log.info("Registration form requested");
        return "form-register";
    }

    /**
     * API 2: Submit registration data
     */
    @PostMapping("/submit")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> submitForm(
            @RequestParam String name,
            @RequestParam String email,
            @RequestParam(required = false) String phone,
            @RequestParam(required = false) String additionalInfo) {

        log.info("Form submission received for: {}", email);

        FormSubmissionEntity submission = formService.createSubmission(name, email, phone, additionalInfo);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("submissionId", submission.getSubmissionId());
        response.put("message", "Form submitted successfully");

        return ResponseEntity.ok(response);
    }

    /**
     * Page 3: Loading page
     */
    @GetMapping("/loading/{submissionId}")
    public String showLoadingPage(@PathVariable String submissionId, Model model) {
        log.info("Loading page requested for submission: {}", submissionId);
        model.addAttribute("submissionId", submissionId);
        return "form-loading";
    }

    /**
     * API 3: Check submission status (polled from loading page)
     */
    @GetMapping("/status/{submissionId}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> checkStatus(@PathVariable String submissionId) {
        try {
            FormSubmissionEntity submission = formService.getSubmissionStatus(submissionId);

            Map<String, Object> response = new HashMap<>();
            response.put("status", submission.getStatus().toString());
            response.put("requiresMfa", submission.getRequiresMfa());

            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    /**
     * Page 4a: MFA Required page
     */
    @GetMapping("/mfa/{submissionId}")
    public String showMfaPage(@PathVariable String submissionId, Model model) {
        log.info("MFA page requested for submission: {}", submissionId);
        model.addAttribute("submissionId", submissionId);
        return "form-mfa";
    }

    /**
     * Page 4b: Success page
     */
    @GetMapping("/success/{submissionId}")
    public String showSuccessPage(@PathVariable String submissionId, Model model) {
        log.info("Success page requested for submission: {}", submissionId);
        model.addAttribute("submissionId", submissionId);
        return "form-success";
    }

    /**
     * Page 4c: Failed page
     */
    @GetMapping("/failed/{submissionId}")
    public String showFailedPage(@PathVariable String submissionId, Model model) {
        log.info("Failed page requested for submission: {}", submissionId);
        model.addAttribute("submissionId", submissionId);
        return "form-failed";
    }
}
