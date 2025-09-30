package org.example.magiclink.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.entity.QRTokenEntity;
import org.example.magiclink.service.QRService;
import org.example.magiclink.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping("/qr")
public class QRController {

    private final QRService qrService;
    private final UserService userService;

    @GetMapping("/generate")
    public String generateQR(Principal principal, HttpServletRequest request, Model model) {
        if (principal == null) {
            return "redirect:/login";
        }

        try {
            String email = principal.getName();
            String deviceInfo = request.getHeader("User-Agent");
            String ip = request.getRemoteAddr();

            QRTokenEntity token = qrService.generateQRToken(email, deviceInfo, ip);
            String qrImage = qrService.generateQRCodeImage(token.getToken());

            model.addAttribute("qrImage", qrImage);
            model.addAttribute("token", token.getToken());
            model.addAttribute("expiresAt", token.getExpiresAt());

            return "qr-generate";
        } catch (Exception e) {
            log.error("Error generating QR code", e);
            return "redirect:/?error=qr_generation_failed";
        }
    }

    @GetMapping("/scan")
    public String scanQR(@RequestParam("token") String token, Model model, HttpServletRequest request) {
        System.out.println("[QRController] /scan called with token: " + token);
        Optional<QRTokenEntity> opt = qrService.validateToken(token);
        System.out.println("[QRController] Token validation result: " + (opt.isPresent() ? "valid" : "invalid"));

        if (opt.isEmpty()) {
            System.out.println("[QRController] Invalid QR token, redirecting to login");
            return "redirect:/login?error=invalid_qr";
        }

        QRTokenEntity qrToken = opt.get();
        System.out.println("[QRController] QRTokenEntity loaded: " + qrToken);

        // Mark as scanned
        if (qrToken.getScannedAt() == null) {
            System.out.println("[QRController] Marking token as scanned at: " + java.time.LocalDateTime.now());
            qrToken.setScannedAt(java.time.LocalDateTime.now());
            qrService.saveToken(qrToken);
            System.out.println("[QRController] Token saved after scan");
        } else {
            System.out.println("[QRController] Token already marked as scanned at: " + qrToken.getScannedAt());
        }

        // Store token in session for polling
        request.getSession(true).setAttribute("pending_qr_token", token);
        System.out.println("[QRController] Token stored in session for polling");

        model.addAttribute("token", token);
        model.addAttribute("userEmail", qrToken.getUserEmail());
        System.out.println("[QRController] Model updated with token and userEmail: " + qrToken.getUserEmail());

        return "qr-scan";
    }

    @GetMapping("/approve")
    public String approveQR(@RequestParam("token") String token, Principal principal, Model model) {
        if (principal == null) {
            return "redirect:/login";
        }

        Optional<QRTokenEntity> opt = qrService.validateToken(token);

        if (opt.isEmpty()) {
            return "redirect:/?error=invalid_qr";
        }

        QRTokenEntity qrToken = opt.get();

        // Verify the logged-in user is the one who generated the QR
        if (!qrToken.getUserEmail().equalsIgnoreCase(principal.getName())) {
            return "redirect:/?error=unauthorized";
        }

        model.addAttribute("token", token);
        model.addAttribute("deviceInfo", qrToken.getDeviceInfo());
        model.addAttribute("ip", qrToken.getIp());

        return "qr-approve";
    }

    @PostMapping("/approve")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> approveQRPost(@RequestParam("token") String token, Principal principal) {
        Map<String, Object> response = new HashMap<>();

        if (principal == null) {
            response.put("success", false);
            response.put("error", "Not authenticated");
            return ResponseEntity.status(401).body(response);
        }

        Optional<QRTokenEntity> opt = qrService.validateToken(token);

        if (opt.isEmpty()) {
            response.put("success", false);
            response.put("error", "Invalid token");
            return ResponseEntity.badRequest().body(response);
        }

        QRTokenEntity qrToken = opt.get();

        if (!qrToken.getUserEmail().equalsIgnoreCase(principal.getName())) {
            response.put("success", false);
            response.put("error", "Unauthorized");
            return ResponseEntity.status(403).body(response);
        }

        boolean approved = qrService.approveToken(token);
        response.put("success", approved);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/deny")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> denyQR(@RequestParam("token") String token, Principal principal) {
        Map<String, Object> response = new HashMap<>();

        if (principal == null) {
            response.put("success", false);
            return ResponseEntity.status(401).body(response);
        }

        Optional<QRTokenEntity> opt = qrService.validateToken(token);

        if (opt.isEmpty()) {
            response.put("success", false);
            return ResponseEntity.badRequest().body(response);
        }

        QRTokenEntity qrToken = opt.get();

        if (!qrToken.getUserEmail().equalsIgnoreCase(principal.getName())) {
            response.put("success", false);
            return ResponseEntity.status(403).body(response);
        }

        boolean denied = qrService.denyToken(token);
        response.put("success", denied);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/status")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> checkStatus(@RequestParam("token") String token, HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();

        QRTokenEntity.QRTokenStatus status = qrService.getTokenStatus(token);
        response.put("status", status.toString());
        response.put("scanned", qrService.wasScanned(token));

        // If approved, consume the token and authenticate
        if (status == QRTokenEntity.QRTokenStatus.APPROVED) {
            Optional<String> emailOpt = qrService.consumeToken(token);

            if (emailOpt.isPresent()) {
                String email = emailOpt.get();

                // Authenticate the user
                UserDetails userDetails = (UserDetails) userService.loadUserByUsername(email);
                Authentication auth = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities()
                );
                SecurityContextHolder.getContext().setAuthentication(auth);
                request.getSession(true);
                userService.updateLastLogin(email);

                response.put("authenticated", true);
                response.put("redirectUrl", "/");
            }
        }

        return ResponseEntity.ok(response);
    }
}