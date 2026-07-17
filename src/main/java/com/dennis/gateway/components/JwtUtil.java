package com.dennis.gateway.components;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtUtil {

    private static final long CLOCK_SKEW_SECONDS = 120;
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
    };

    @Value("${jwt.secret}")
    private String secret;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public Map<String, Object> parseToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT structure");
        }

        Map<String, Object> header = decodeJsonPart(parts[0]);
        Object alg = header.get("alg");
        if (!"HS256".equals(alg)) {
            throw new IllegalArgumentException("Unsupported JWT algorithm");
        }

        String signedContent = parts[0] + "." + parts[1];
        String expectedSignature = sign(signedContent);
        if (!MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8),
                parts[2].getBytes(StandardCharsets.UTF_8))) {
            throw new IllegalArgumentException("Invalid JWT signature");
        }

        Map<String, Object> claims = decodeJsonPart(parts[1]);
        validateExpiration(claims);
        return claims;
    }

    private Map<String, Object> decodeJsonPart(String base64UrlPart) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(base64UrlPart);
            return objectMapper.readValue(decoded, MAP_TYPE);
        } catch (IllegalArgumentException | IOException e) {
            throw new IllegalArgumentException("Invalid JWT JSON part", e);
        }
    }

    private String sign(String content) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] signature = mac.doFinal(content.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to sign JWT content", e);
        }
    }

    private void validateExpiration(Map<String, Object> claims) {
        Object expObj = claims.get("exp");
        if (expObj == null) {
            throw new IllegalArgumentException("Missing exp claim");
        }

        long expSeconds;
        if (expObj instanceof Number number) {
            expSeconds = number.longValue();
        } else {
            try {
                expSeconds = Long.parseLong(String.valueOf(expObj));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid exp claim", e);
            }
        }

        long now = Instant.now().getEpochSecond();
        if (now > expSeconds + CLOCK_SKEW_SECONDS) {
            throw new IllegalArgumentException("JWT expired");
        }
    }

    @EventListener(ApplicationReadyEvent.class)
    public void logSecretFingerprint() {
        log.info("Gateway JWT secret fingerprint: {}", fingerprint(secret));
    }

    private String fingerprint(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));

            StringBuilder firstBytes = new StringBuilder();
            for (int i = 0; i < 4; i++) {
                firstBytes.append(String.format("%02x", hash[i]));
            }

            return "len=" + value.length() + ", sha256[0..7]=" + firstBytes;
        } catch (NoSuchAlgorithmException e) {
            return "sha256_unavailable";
        }
    }

}
