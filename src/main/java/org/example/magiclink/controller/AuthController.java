package org.example.magiclink.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.entity.FormProcessingStatus;
import org.example.magiclink.entity.User;
import org.example.magiclink.service.EmailService;
import org.example.magiclink.service.FormProcessingService;
import org.example.magiclink.service.TokenService;
import org.example.magiclink.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Controller
@RequiredArgsConstructor
public class AuthController {

    private final TokenService tokenService;
    private final EmailService emailService;
    private final UserService userService;
    private final FormProcessingService formProcessingService;

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/login/ott/generate")
    public String generateToken(HttpServletRequest request, @RequestParam("username") String username) {
        String email = username == null ? null : username.trim().toLowerCase();
        if (email == null || email.isEmpty()) {
            return "redirect:/login?error";
        }

        // Check if user has a Google account
        if (!userService.hasGoogleAccount(email)) {
            return "redirect:/login?error=no_google_account";
        }

        String token = tokenService.createToken(email, request);

        String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "") + request.getContextPath();
        String magicLink = baseUrl + "/login/ott?token=" + token;

        emailService.sendMagicLink(email, magicLink);

        return "redirect:/check-email";
    }

    @GetMapping("/check-email")
    public String checkEmail() {
        return "check-email";
    }

    @GetMapping("/login/ott")
    public String consumeToken(
            HttpServletRequest request,
            @RequestParam("token") String token,
            Model model) {

        // Validate token without consuming it yet
        Optional<String> emailOpt = tokenService.validateToken(token);
        if (emailOpt.isEmpty()) {
            return "redirect:/login?error=invalid_token";
        }

        String expectedEmail = emailOpt.get();

        // Store token in session for verification after OAuth
        HttpSession session = request.getSession(true);
        session.setAttribute("pending_magic_token", token);
        session.setAttribute("pending_magic_email", expectedEmail);

        model.addAttribute("email", expectedEmail);
        model.addAttribute("token", token);

        // Get or create processing status entry
        formProcessingService.getOrCreateStatus(token, expectedEmail);

        // Redirect to multi-page form
        return "magic-link-multipage";
    }

    @GetMapping("/login/ott/verify-manual")
    public String verifyManual(HttpSession session, Model model) {
        String expectedEmail = (String) session.getAttribute("pending_magic_email");
        if (expectedEmail == null) {
            return "redirect:/login?error=session_expired";
        }
        model.addAttribute("email", expectedEmail);
        return "verify-manual";
    }

    /**
     * Process form data submitted from magic link form
     */
    @PostMapping("/magic-link/process-form")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> processFormData(
            @RequestParam String token,
            @RequestBody Map<String, String> formData,
            HttpSession session) {

        log.info("Processing form data for token: {}", token);

        // Validate the magic link token
        Optional<String> emailOpt = tokenService.validateToken(token);
        if (emailOpt.isEmpty()) {
            log.warn("Invalid or expired token: {}", token);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", "Invalid or expired token");
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
     * Check the processing status of form submission
     */
    @GetMapping("/magic-link/check-status")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> checkProcessingStatus(@RequestParam String token) {
        log.debug("Checking processing status for token: {}", token);

        Optional<FormProcessingStatus> statusOpt = formProcessingService.getStatus(token);
        if (statusOpt.isEmpty()) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", "Processing status not found");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }

        FormProcessingStatus status = statusOpt.get();
        Map<String, Object> response = new HashMap<>();

        if (status.getStatus() == FormProcessingStatus.ProcessingStatus.COMPLETED) {
            // Mark token as consumed and authenticate user
            tokenService.validateAndConsume(token);
            authenticateUser(null, status.getEmail());

            response.put("status", "completed");
            response.put("progress", 100);
            response.put("nextStep", "/");
        } else if (status.getStatus() == FormProcessingStatus.ProcessingStatus.FAILED) {
            response.put("status", "failed");
            response.put("message", status.getErrorMessage());
        } else {
            response.put("status", "processing");
            response.put("progress", status.getProgress());
        }

        return ResponseEntity.ok(response);
    }

    private void authenticateUser(HttpServletRequest request, String email) {
        UserDetails userDetails = (UserDetails) userService.loadUserByUsername(email);
        Authentication auth = new UsernamePasswordAuthenticationToken(
            userDetails, null, userDetails.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
        request.getSession(true);
        userService.updateLastLogin(email);
    }
}