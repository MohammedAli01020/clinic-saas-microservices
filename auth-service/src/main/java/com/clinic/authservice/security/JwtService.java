package com.clinic.authservice.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Component
@Slf4j
public class JwtService {

    @Value("${app.jwt.private-key-pem}")
    private String privateKeyPem;

    @Value("${app.jwt.issuer:clinic-auth}")
    private String issuer;

    @Value("${app.jwt.access-exp-minutes:15}")
    private long accessExpMinutes;

    @Value("${app.jwt.refresh-exp-days:30}")
    private long refreshExpDays;

    private Algorithm algorithm;

    @PostConstruct
    public void init() {

        try {
            PrivateKey privateKey = parsePrivateKey(privateKeyPem);

            this.algorithm = Algorithm.RSA256(null, (RSAPrivateKey) privateKey);
            log.info("JWT Service initialized using RSA");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize JWT Service", e);
        }
    }

    public String generateAccessToken(
            String subjectId,
            String tenantId,
            Boolean isEnabled,
            String role,
            List<String> permissions
    ) {
        Instant now = Instant.now();
        return JWT.create()
                .withIssuer(issuer)
                .withSubject(subjectId)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusSeconds(accessExpMinutes * 60)))
                .withClaim("tenantId", tenantId)
                .withClaim("role", role)
                .withClaim("isEnabled", isEnabled)
                .withClaim("permissions", permissions)
                .withClaim("tokenType", "access")
                .withClaim("principalType", "USER")
                .sign(algorithm);
    }


    public String generateEmailVerificationToken(String subjectId) {
        Instant now = Instant.now();
        return JWT.create()
                .withIssuer(issuer)
                .withSubject(subjectId)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusSeconds(15 * 60))) // 15 دقيقة
                .withClaim("tokenType", "email_verification")
                .sign(algorithm);
    }


    public String generateRefreshToken(String subjectId) {
        Instant now = Instant.now();
        return JWT.create()
                .withIssuer(issuer)
                .withSubject(subjectId)
                .withClaim("tokenType", "refresh")
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusSeconds(refreshExpDays * 86400)))
                .sign(algorithm);
    }

    public DecodedJWT verify(String token) {
        return JWT.require(algorithm)
                .withIssuer(issuer)
                .build()
                .verify(token);
    }

    public long getRefreshExpirySeconds() {
        return refreshExpDays * 86400;
    }

    // ===== Key parsing =====

    private PrivateKey parsePrivateKey(String key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(cleanPem(key));
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    private PublicKey parsePublicKey(String key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(cleanPem(key));
        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decoded));
    }

    private String cleanPem(String pem) {
        return pem
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\\s+", "");
    }
}

