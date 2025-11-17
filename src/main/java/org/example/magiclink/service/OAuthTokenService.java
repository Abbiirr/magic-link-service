package org.example.magiclink.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuthTokenService {

    @Value("${GOOGLE_CLIENT_ID:83857630873-3um7tnfj5jmpjdk3uuvrfugg8j9d59ph.apps.googleusercontent.com}")
    private String clientId;

    @Value("${GOOGLE_CLIENT_SECRET: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}")
    private String clientSecret;

    private final RestTemplate restTemplate = new RestTemplate();

    // Store tokens with their metadata
    private final Map<String, TokenInfo> tokenStore = new ConcurrentHashMap<>();

    /**
     * Generate OAuth token using client credentials flow
     */
    public String generateOAuthToken() {
        try {
            log.info("Generating OAuth token using client credentials");

            // Google doesn't support client credentials grant for their standard OAuth
            // So we'll create a custom token that can be validated later
            // This token will be used to identify the registration flow

            String token = java.util.UUID.randomUUID().toString();

            // Store token info
            TokenInfo tokenInfo = new TokenInfo();
            tokenInfo.setToken(token);
            tokenInfo.setClientId(clientId);
            tokenInfo.setCreatedAt(System.currentTimeMillis());
            tokenInfo.setExpiresIn(3600000); // 1 hour

            tokenStore.put(token, tokenInfo);

            log.info("Generated token: {}", token);
            return token;

        } catch (Exception e) {
            log.error("Error generating OAuth token", e);
            throw new RuntimeException("Failed to generate OAuth token", e);
        }
    }

    /**
     * Validate if token exists and is not expired
     */
    public boolean validateToken(String token) {
        TokenInfo tokenInfo = tokenStore.get(token);

        if (tokenInfo == null) {
            log.warn("Token not found: {}", token);
            return false;
        }

        long currentTime = System.currentTimeMillis();
        long expiresAt = tokenInfo.getCreatedAt() + tokenInfo.getExpiresIn();

        if (currentTime > expiresAt) {
            log.warn("Token expired: {}", token);
            tokenStore.remove(token);
            return false;
        }

        log.info("Token is valid: {}", token);
        return true;
    }

    /**
     * Consume token (mark as used)
     */
    public void consumeToken(String token) {
        tokenStore.remove(token);
        log.info("Token consumed: {}", token);
    }

    /**
     * Get token info
     */
    public TokenInfo getTokenInfo(String token) {
        return tokenStore.get(token);
    }

    // Inner class to store token metadata
    public static class TokenInfo {
        private String token;
        private String clientId;
        private long createdAt;
        private long expiresIn;

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public long getCreatedAt() {
            return createdAt;
        }

        public void setCreatedAt(long createdAt) {
            this.createdAt = createdAt;
        }

        public long getExpiresIn() {
            return expiresIn;
        }

        public void setExpiresIn(long expiresIn) {
            this.expiresIn = expiresIn;
        }
    }
}
