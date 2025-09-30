package org.example.magiclink.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
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
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import jakarta.servlet.http.HttpServletResponse;

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
            String email = extractEmail(principal);
            String deviceInfo = request.getHeader("User-Agent");
            String ip = request.getRemoteAddr();
            String sessionId = request.getSession().getId();

            QRTokenEntity token = qrService.generateQRToken(email, deviceInfo, ip, sessionId);
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

    private String extractEmail(Principal principal) {
        if (principal instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauth = (OAuth2AuthenticationToken) principal;
            OAuth2User oauth2User = oauth.getPrincipal();
            return oauth2User.getAttribute("email");
        }
        return principal.getName();
    }

    @GetMapping("/scan")
    public String scanQR(@RequestParam("token") String token, Model model, HttpServletRequest request) {
        Optional<QRTokenEntity> opt = qrService.validateToken(token);

        if (opt.isEmpty()) {
            return "redirect:/login?error=invalid_qr";
        }

        QRTokenEntity qrToken = opt.get();

        // Prevent self-consumption
        String currentSessionId = request.getSession().getId();
        if (qrToken.getGeneratingSessionId().equals(currentSessionId)) {
            return "redirect:/login?error=cannot_scan_own_qr";
        }

        // Mark as scanned
        if (qrToken.getScannedAt() == null) {
            qrToken.setScannedAt(java.time.LocalDateTime.now());
            qrService.saveToken(qrToken);
        }

        // Store token in session for polling
        request.getSession(true).setAttribute("pending_qr_token", token);

        model.addAttribute("token", token);
        model.addAttribute("userEmail", qrToken.getUserEmail());

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
        String email = extractEmail(principal);

        // Verify the logged-in user is the one who generated the QR
        if (!qrToken.getUserEmail().equalsIgnoreCase(email)) {
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

        String email = extractEmail(principal);
        Optional<QRTokenEntity> opt = qrService.validateToken(token);

        if (opt.isEmpty()) {
            response.put("success", false);
            response.put("error", "Invalid token");
            return ResponseEntity.badRequest().body(response);
        }

        QRTokenEntity qrToken = opt.get();

        if (!qrToken.getUserEmail().equalsIgnoreCase(email)) {
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

        String email = extractEmail(principal);
        Optional<QRTokenEntity> opt = qrService.validateToken(token);

        if (opt.isEmpty()) {
            response.put("success", false);
            return ResponseEntity.badRequest().body(response);
        }

        QRTokenEntity qrToken = opt.get();

        if (!qrToken.getUserEmail().equalsIgnoreCase(email)) {
            response.put("success", false);
            return ResponseEntity.status(403).body(response);
        }

        boolean denied = qrService.denyToken(token);
        response.put("success", denied);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/status")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> checkStatus(
            @RequestParam("token") String token,
            HttpServletRequest request,
            HttpServletResponse response) {

        Map<String, Object> responseMap = new HashMap<>();
        String requestIP = request.getRemoteAddr();

        QRTokenEntity.QRTokenStatus status = qrService.getTokenStatus(token);
        responseMap.put("status", status.toString());
        responseMap.put("scanned", qrService.wasScanned(token));

        System.out.println("[Status] IP: " + requestIP + ", Token: " + token + ", Status: " + status);

        HttpSession session = request.getSession(false);
        String pendingToken = session != null ? (String) session.getAttribute("pending_qr_token") : null;

        System.out.println("[Status] Pending: " + pendingToken + ", Match: " + token.equals(pendingToken));

        if (token.equals(pendingToken)) {
            Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
            boolean alreadyAuth = currentAuth != null &&
                    currentAuth.isAuthenticated() &&
                    !"anonymousUser".equals(currentAuth.getName());

            System.out.println("[Status] Already auth: " + alreadyAuth + " (user: " +
                    (currentAuth != null ? currentAuth.getName() : "null") + ")");

            if (alreadyAuth) {
                responseMap.put("authenticated", true);
                responseMap.put("redirectUrl", "/");
            } else if (status == QRTokenEntity.QRTokenStatus.APPROVED) {
                System.out.println("[Status] Starting authentication for IP: " + requestIP);

                try {
                    Optional<String> emailOpt = qrService.consumeToken(token);
                    System.out.println("[Status] consumeToken result: " + emailOpt.isPresent());

                    if (emailOpt.isPresent()) {
                        String email = emailOpt.get();
                        System.out.println("[Status] Loading user: " + email);

                        UserDetails userDetails = (UserDetails) userService.loadUserByUsername(email);
                        System.out.println("[Status] UserDetails loaded: " + userDetails.getUsername());

                        Authentication auth = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities()
                        );

                        SecurityContextHolder.getContext().setAuthentication(auth);
                        System.out.println("[Status] Auth set in SecurityContext");

                        HttpSession newSession = request.getSession(true);
                        System.out.println("[Status] Session ID: " + newSession.getId());

                        SecurityContextRepository securityContextRepository =
                                new HttpSessionSecurityContextRepository();
                        securityContextRepository.saveContext(
                                SecurityContextHolder.getContext(), request, response
                        );
                        System.out.println("[Status] SecurityContext saved to session");

                        userService.updateLastLogin(email);

                        responseMap.put("authenticated", true);
                        responseMap.put("redirectUrl", "/");
                        System.out.println("[Status] ✓ Auth SUCCESS for " + email + " from IP: " + requestIP);
                    } else {
                        System.out.println("[Status] ✗ consumeToken returned empty");
                    }
                } catch (Exception e) {
                    System.out.println("[Status] ✗ EXCEPTION during auth: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } else {
            System.out.println("[Status] Skipping - different device (IP: " + requestIP + ")");
        }

        return ResponseEntity.ok(responseMap);
    }
}