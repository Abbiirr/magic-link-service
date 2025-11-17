package org.example.magiclink.controller;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.entity.FormSubmissionEntity;
import org.example.magiclink.service.FormService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Controller
@RequestMapping("/form")
@RequiredArgsConstructor
@Slf4j
public class FormController {

    private final FormService formService;

    @Value("${app.magic-link.base-url}")
    private String baseUrl;

    /**
     * API 1: Generate magic link (no auth, no params)
     */
    @GetMapping("/generate-link")
    public String generateMagicLink(Model model) {
        // Generate a unique token for this registration flow
        String token = UUID.randomUUID().toString();

        // Create the magic link URL
        String magicLink = baseUrl + "/form/verify?token=" + token;

        log.info("Generated form magic link with token: {}", token);

        model.addAttribute("magicLink", magicLink);
        model.addAttribute("token", token);

        return "form-link-generated";
    }

    /**
     * Handle magic link click - initiates OAuth flow
     */
    @GetMapping("/verify")
    public String verifyMagicLink(@RequestParam String token, HttpSession session) {
        log.info("Form magic link clicked with token: {}", token);

        // Store token in session for later use
        session.setAttribute("form_token", token);

        // Redirect to OAuth2 authorization with Google
        return "redirect:/oauth2/authorization/google";
    }

    /**
     * Page 2: Registration form page (after OAuth)
     */
    @GetMapping("/register")
    public String showRegistrationForm(HttpSession session, Model model) {
        String oauthEmail = (String) session.getAttribute("form_oauth_email");
        String formToken = (String) session.getAttribute("form_token");

        if (oauthEmail == null || formToken == null) {
            log.warn("Registration form accessed without proper OAuth flow");
            return "redirect:/form/generate-link";
        }

        model.addAttribute("email", oauthEmail);
        log.info("Showing form registration page for email: {}", oauthEmail);

        return "form-register";
    }

    /**
     * API 2: Submit registration data - shows loading page
     */
    @PostMapping("/submit")
    public String submitForm(
            @RequestParam String name,
            @RequestParam String email,
            @RequestParam String password,
            HttpSession session,
            Model model) {

        log.info("Form submission received - name: {}, email: {}", name, email);

        // Here you would typically:
        // 1. Validate the data
        // 2. Create/update user in database
        // 3. Store password securely (hashed)
        // 4. Link with OAuth data from session

        String oauthEmail = (String) session.getAttribute("form_oauth_email");
        String googleId = (String) session.getAttribute("form_oauth_google_id");
        String formToken = (String) session.getAttribute("form_token");

        log.info("OAuth email: {}, Google ID: {}, Token: {}", oauthEmail, googleId, formToken);

        // Clean up session
        session.removeAttribute("form_token");
        session.removeAttribute("form_oauth_email");
        session.removeAttribute("form_oauth_google_id");

        // Show loading page (as requested - keep loading)
        model.addAttribute("name", name);
        model.addAttribute("email", email);

        return "form-loading";
    }

}
