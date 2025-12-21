package com.clinic.gatewayservice;

import com.clinic.sharedlib.jwt.CurrentUser;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 * JwtUtils: stateless helper to parse JWT (supports RS256 publicKey or HMAC
 * secret).
 * - parseWithPublicKey: verify signature with RSA public key
 * - parseWithHmac: verify with HMAC secret (base64 encoded)
 * - parseTokenAuto: tries publicKey first, then HMAC secret
 * <p>
 * Security note: keys/secrets must be stored in secure vault in production.
 */
@Component
public class JwtUtils {

    @Value("${security.jwt.public-key}")
    private String publicKeyPem;

    private PublicKey publicKey;


    @PostConstruct
    public void init() throws Exception {

        if (publicKeyPem != null && !publicKeyPem.isBlank()) {
            publicKey = parsePublicKey(publicKeyPem);
        }
    }


    public Jws<Claims> parseWithPublicKey(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token);

    }


    public CurrentUser parseTokenAuto(String token) {
        Jws<Claims> parsed = parseWithPublicKey(token);
        return toUserInfo(parsed);
    }

    public boolean validateJwtToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException ex) {
            return false;
        }

    }

    private PublicKey parsePublicKey(String key) throws Exception {

        String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");


        byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);

        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    public String getClaim(String token, String claimName) {
        return parseWithPublicKey(token).getBody().get(claimName, String.class);
    }


    public CurrentUser toUserInfo(Jws<Claims> parsed) {
        Claims c = parsed.getBody();
        String userId = c.getSubject();
        String email = c.get("email", String.class);
        String tenant = c.get("tenant") != null ? c.get("tenant", String.class)
                : c.get("tenantId", String.class);
        List<String> rolesList = c.get("roles", List.class);
        Set<String> roles = rolesList != null ? Set.copyOf(rolesList) : Set.of();
        boolean emailVerified = c.get("emailVerified", Boolean.class) != null
                ? c.get("emailVerified", Boolean.class)
                : false;
        boolean enabled = c.get("enabled", Boolean.class) != null
                ? c.get("enabled", Boolean.class)
                : true;
        Instant issued =
                c.getIssuedAt() != null ? c.getIssuedAt().toInstant() : Instant.EPOCH;
        Instant expires = c.getExpiration() != null ? c.getExpiration().toInstant()
                : Instant.EPOCH;
        return new CurrentUser(userId, email, tenant, roles, emailVerified, enabled,
                issued, expires);
    }
}




