package com.clinic.sharedinternaltokengen;


import com.clinic.sharedsecurityjwt.*;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class InternalTokenVerifier {

    @Value("${app.jwt.internal-public-key-pem}")
    private String internalPublicKeyPem;

    @Value("${spring.application.name}")
    private String currentServiceName;

    private PublicKey publicKey;

    private final Set<String> allowedIssuers = Set.of(
            "auth-service",
            "gateway-service",
            "tenant-service",
            "user-management-service"
    );

    @PostConstruct
    public void init() {
        try {
            publicKey = parsePublicKey(internalPublicKeyPem);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize JWT Service", e);
        }
    }

    private static boolean isTrue(Claims claims, String key) {
        return Boolean.TRUE.equals(claims.get(key, Boolean.class));
    }

    /**
     * Verify internal JWT token
     */
    public SecurityPrincipal verify(String token) {

        Claims claims = Jwts.parser()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // ───────────────── issuer ─────────────────
        String issuer = claims.getIssuer();
        if (!allowedIssuers.contains(issuer)) {
            throw new SecurityException("Unauthorized token issuer: " + issuer);
        }

        // ───────────────── principal type ─────────────────
        String type = claims.get("principalType", String.class);
        if (type == null) {
            throw new SecurityException("Missing token type");
        }

        // ───────────────── audience (FIX) ─────────────────
        Set<String> aud = extractSet(claims.getAudience());

//        String aud;
//
//        if (audClaim instanceof String s) {
//            aud = s;
//        } else if (audClaim instanceof Collection<?> c && !c.isEmpty()) {
//            aud = c.iterator().next().toString();
//        } else {
//            throw new SecurityException("Invalid audience claim");
//        }
//
        if (!aud.contains(currentServiceName)) {
            throw new SecurityException("Token audience mismatch for service: " + currentServiceName);
        }


        // ───────────────── SERVICE token ─────────────────
        if (PrincipalType.SERVICE.name().equals(type)) {



            return ServicePrincipal.builder()
                    .sub(claims.getSubject())
                    .scopes(extractSet(claims.get("scopes")))
                    .tenantId(claims.get("tenantId", String.class))
                    .aud(aud)
                    .iss(issuer)
                    .issuedAt(claims.getIssuedAt().toInstant())
                    .expiresAt(claims.getExpiration().toInstant())
                    .principalType(PrincipalType.SERVICE)
                    .build();

        }

        // ───────────────── USER token ─────────────────
        if (PrincipalType.USER.name().equals(type)) {

            return UserPrincipal.builder()
                    .sub(claims.getSubject())
                    .aud(aud)
                    .role(claims.get("role", String.class))
                    .permissions(extractSet(claims.get("permissions")))
                    .tenantId(claims.get("tenantId", String.class))
                    .email(claims.get("email", String.class))
                    .iss(issuer)
                    .issuedAt(claims.getIssuedAt().toInstant())
                    .expiresAt(claims.getExpiration().toInstant())
                    .principalType(PrincipalType.USER)
                    .isEnabled(isTrue(claims, "isEnabled"))
                    .build();
        }

        throw new SecurityException("Unknown principal type: " + type);
    }

    // ───────────────── helpers ─────────────────

    @SuppressWarnings("unchecked")
    private static Set<String> extractSet(Object claim) {
        if (claim instanceof Collection<?> collection) {
            return collection.stream()
                    .map(String::valueOf)
                    .collect(Collectors.toUnmodifiableSet());
        }
        return Set.of();
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
