package org.example.magiclink.controller;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.entity.FormSubmissionEntity;
import org.example.magiclink.service.FormService;
import org.example.magiclink.service.MagicLinkService;
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
    private final MagicLinkService magicLinkService;

    /**
     * API 1: Generate magic link with OAuth token (no auth, no params)
     * Returns JSON response with the magic link
     */
    @GetMapping("/generate-link")
    @ResponseBody
    public ResponseEntity<Map<String, String>> generateMagicLink() {
        log.info("Generating magic link for form registration");

        // Generate magic link with OAuth token
        MagicLinkService.MagicLinkResponse response = magicLinkService.generateMagicLink("/form/verify");

        Map<String, String> result = new HashMap<>();
        result.put("magicLink", response.getMagicLink());
        result.put("token", response.getToken());

        log.info("Generated magic link: {}", response.getMagicLink());

        return ResponseEntity.ok(result);
    }

    /**
     * Handle magic link click - verify token and show form directly
     */
    @GetMapping("/verify")
    public String verifyMagicLink(@RequestParam String token, HttpSession session, Model model) {
        log.info("Form magic link clicked with token: {}", token);

        // Validate the OAuth token
        if (!magicLinkService.validateToken(token)) {
            log.warn("Invalid or expired token: {}", token);
            return "redirect:/form/generate-link?error=invalid_token";
        }

        // Store token in session for later use
        session.setAttribute("form_token", token);

        // Redirect to OAuth2 authorization with Revo to get user info
        return "redirect:/oauth2/authorization/revo";
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

        // Validate token is still valid
        if (!magicLinkService.validateToken(formToken)) {
            log.warn("Token expired during registration flow");
            return "redirect:/form/generate-link?error=token_expired";
        }

        model.addAttribute("email", oauthEmail);
        model.addAttribute("token", formToken);
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

        String oauthEmail = (String) session.getAttribute("form_oauth_email");
        String userId = (String) session.getAttribute("form_oauth_user_id");
        String formToken = (String) session.getAttribute("form_token");

        log.info("OAuth email: {}, User ID: {}, Token: {}", oauthEmail, userId, formToken);

        // Consume the token (one-time use)
        if (formToken != null) {
            magicLinkService.consumeToken(formToken);
        }

        // Clean up session
        session.removeAttribute("form_token");
        session.removeAttribute("form_oauth_email");
        session.removeAttribute("form_oauth_user_id");

        // Show loading page (as requested - keep loading)
        model.addAttribute("name", name);
        model.addAttribute("email", email);

        return "form-loading";
    }

}
