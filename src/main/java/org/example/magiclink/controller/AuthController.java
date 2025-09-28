package org.example.magiclink.controller;

import lombok.RequiredArgsConstructor;
import org.example.magiclink.service.EmailService;
import org.example.magiclink.service.TokenService;
import org.example.magiclink.service.UserService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
        // normalize
        String email = username == null ? null : username.trim().toLowerCase();
        if (email == null || email.isEmpty()) {
            return "redirect:/login?error";
        }

        // ensure user exists
        userService.findOrCreate(email);

        // create token
        String token = tokenService.createToken(email, request);

        // build magic link
        String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "") + request.getContextPath();
        String magicLink = baseUrl + "/login/ott?token=" + token;

        // send email (async recommended in real app)
        emailService.sendMagicLink(email, magicLink);

        return "redirect:/check-email";
    }

    @GetMapping("/check-email")
    public String checkEmail() {
        return "check-email";
    }

    @GetMapping("/login/ott")
    public String consumeToken(HttpServletRequest request, HttpServletResponse response, @RequestParam("token") String token) throws IOException {
        Optional<String> opt = tokenService.validateAndConsume(token);
        if (opt.isEmpty()) {
            return "redirect:/login?error";
        }
        String username = opt.get();
        UserDetails userDetails = (UserDetails) userService.loadUserByUsername(username);
        Authentication auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);
        // create session
        request.getSession(true);
        // update last login
        userService.updateLastLogin(username);
        return "redirect:/";
    }
}

