package org.example.magiclink.controller;

import lombok.RequiredArgsConstructor;
import org.example.magiclink.service.EmailService;
import org.example.magiclink.service.TokenService;
import org.example.magiclink.service.UserService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
public class AuthController {

    private final TokenService tokenService;
    private final EmailService emailService;
    private final UserService userService;

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

        userService.findOrCreate(email);
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
            HttpServletResponse response,
            @RequestParam("token") String token,
            Authentication authentication) throws IOException {

        // Validate the token first
        Optional<String> opt = tokenService.validateAndConsume(token);
        if (opt.isEmpty()) {
            return "redirect:/login?error";
        }

        String expectedEmail = opt.get();

        // Check if user is already authenticated via Google OAuth2
        if (authentication != null && authentication.isAuthenticated()
                && authentication instanceof OAuth2AuthenticationToken) {

            OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
            OAuth2User oauth2User = oauth2Token.getPrincipal();
            String googleEmail = oauth2User.getAttribute("email");

            // Verify the Google email matches the magic link email
            if (googleEmail != null && googleEmail.equalsIgnoreCase(expectedEmail)) {
                // User is authenticated with correct Google account
                authenticateUser(request, expectedEmail);
                return "redirect:/";
            } else {
                // Google email doesn't match - need to re-authenticate
                HttpSession session = request.getSession(true);
                session.setAttribute("pending_magic_link_email", expectedEmail);
                session.setAttribute("pending_magic_link_token", token);
                return "redirect:/login/ott/verify-google";
            }
        }

        // User is not authenticated with Google - store token and redirect to Google login
        HttpSession session = request.getSession(true);
        session.setAttribute("pending_magic_link_email", expectedEmail);
        session.setAttribute("pending_magic_link_token", token);

        return "redirect:/login/ott/verify-google";
    }

    @GetMapping("/login/ott/verify-google")
    public String verifyGooglePage(HttpSession session, Model model) {
        String expectedEmail = (String) session.getAttribute("pending_magic_link_email");
        if (expectedEmail == null) {
            return "redirect:/login?error";
        }
        model.addAttribute("email", expectedEmail);
        return "verify-google";
    }

    @GetMapping("/oauth2/success")
    public String oauth2Success(HttpServletRequest request, OAuth2AuthenticationToken authentication) {
        HttpSession session = request.getSession(false);

        if (session != null) {
            String expectedEmail = (String) session.getAttribute("pending_magic_link_email");

            if (expectedEmail != null) {
                OAuth2User oauth2User = authentication.getPrincipal();
                String googleEmail = oauth2User.getAttribute("email");

                // Verify emails match
                if (googleEmail != null && googleEmail.equalsIgnoreCase(expectedEmail)) {
                    authenticateUser(request, expectedEmail);

                    // Clean up session
                    session.removeAttribute("pending_magic_link_email");
                    session.removeAttribute("pending_magic_link_token");

                    return "redirect:/";
                } else {
                    return "redirect:/login?error=email_mismatch";
                }
            }
        }

        // If no pending magic link, just redirect to home
        return "redirect:/";
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