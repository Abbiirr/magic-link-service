package org.example.magiclink.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.entity.QRTokenEntity;
import org.example.magiclink.repository.QRTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class QRService {

    private final QRTokenRepository qrTokenRepository;

    @Value("${app.qr-login.token-expiry-minutes:5}")
    private int tokenExpiryMinutes;

    @Value("${app.magic-link.base-url:http://localhost:8080}")
    private String baseUrl;

    public QRTokenEntity generateQRToken(String userEmail, String deviceInfo, String ip) {
        String token = UUID.randomUUID().toString();

        QRTokenEntity entity = new QRTokenEntity();
        entity.setToken(token);
        entity.setUserEmail(userEmail);
        entity.setExpiresAt(LocalDateTime.now().plusMinutes(tokenExpiryMinutes));
        entity.setStatus(QRTokenEntity.QRTokenStatus.PENDING);
        entity.setDeviceInfo(deviceInfo);
        entity.setIp(ip);

        return qrTokenRepository.save(entity);
    }

    public String generateQRCodeImage(String token) throws Exception {
        String qrUrl = baseUrl + "/qr/scan?token=" + token;

        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(qrUrl, BarcodeFormat.QR_CODE, 300, 300);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);

        byte[] imageBytes = outputStream.toByteArray();
        return "data:image/png;base64," + Base64.getEncoder().encodeToString(imageBytes);
    }

    public Optional<QRTokenEntity> validateToken(String token) {
        Optional<QRTokenEntity> opt = qrTokenRepository.findByToken(token);
        if (opt.isEmpty()) return Optional.empty();

        QRTokenEntity entity = opt.get();

        // Check if expired
        if (entity.getExpiresAt().isBefore(LocalDateTime.now())) {
            entity.setStatus(QRTokenEntity.QRTokenStatus.EXPIRED);
            qrTokenRepository.save(entity);
            return Optional.empty();
        }

        return opt;
    }

    public boolean approveToken(String token) {
        Optional<QRTokenEntity> opt = validateToken(token);
        if (opt.isEmpty()) return false;

        QRTokenEntity entity = opt.get();
        if (entity.getStatus() != QRTokenEntity.QRTokenStatus.PENDING) {
            return false;
        }

        entity.setStatus(QRTokenEntity.QRTokenStatus.APPROVED);
        qrTokenRepository.save(entity);
        log.info("QR token approved: {}", token);
        return true;
    }

    public boolean denyToken(String token) {
        Optional<QRTokenEntity> opt = validateToken(token);
        if (opt.isEmpty()) return false;

        QRTokenEntity entity = opt.get();
        entity.setStatus(QRTokenEntity.QRTokenStatus.DENIED);
        qrTokenRepository.save(entity);
        log.info("QR token denied: {}", token);
        return true;
    }

    public Optional<String> consumeToken(String token) {
        Optional<QRTokenEntity> opt = validateToken(token);
        if (opt.isEmpty()) return Optional.empty();

        QRTokenEntity entity = opt.get();
        if (entity.getStatus() != QRTokenEntity.QRTokenStatus.APPROVED) {
            return Optional.empty();
        }

        entity.setStatus(QRTokenEntity.QRTokenStatus.CONSUMED);
        qrTokenRepository.save(entity);

        return Optional.of(entity.getUserEmail());
    }

    public QRTokenEntity.QRTokenStatus getTokenStatus(String token) {
        return qrTokenRepository.findByToken(token)
            .map(QRTokenEntity::getStatus)
            .orElse(QRTokenEntity.QRTokenStatus.EXPIRED);
    }

    public void saveToken(QRTokenEntity token) {
        qrTokenRepository.save(token);
    }

    public boolean wasScanned(String token) {
        return qrTokenRepository.findByToken(token)
            .map(e -> e.getScannedAt() != null)
            .orElse(false);
    }
}