package com.clinic.sharedinternaltokengen;

import com.clinic.sharedsecurityjwt.*;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import java.util.Base64;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class InternalTokenVerifier {

    @Value("${app.jwt.internal-public-key-pem}")
    private String publicKeyPem;

    @Value("${app.service.name}")
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
            publicKey = parsePublicKey(publicKeyPem);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize JWT Service", e);
        }
    }

    private static boolean isTrue(Claims claims, String key) {
        return Boolean.TRUE.equals(claims.get(key, Boolean.class));
    }


    /**
     * Verify internal JWT token
     * @param token JWT token
     * @return SecurityPrincipal
     */
    public SecurityPrincipal verify(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        String type = claims.get("principalType", String.class);
        if (type == null) throw new SecurityException("Missing token type");

        String issuer = claims.getIssuer();
        if (!allowedIssuers.contains(issuer)) {
            throw new SecurityException("Unauthorized token issuer: " + issuer);
        }

        if (PrincipalType.SERVICE.name().equals(type)) {
            String aud = claims.get("aud", String.class);
            if (aud == null || !aud.equals(currentServiceName)) {
                throw new SecurityException("Token audience mismatch for service: " + currentServiceName);
            }
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

        } else if (PrincipalType.USER.name().equals(type)) {
            return UserPrincipal.builder()
                    .sub(claims.getSubject())
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
        } else {
            throw new SecurityException("Unknown principal type: " + type);
        }
    }

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
