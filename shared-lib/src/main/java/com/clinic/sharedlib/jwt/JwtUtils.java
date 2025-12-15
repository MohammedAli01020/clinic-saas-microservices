package com.clinic.sharedlib.jwt;

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
    private String publicKey;

    private PublicKey publicKeyK;


    @PostConstruct
    public void init() throws Exception {

//        String pubPem = Files.readString(java.nio.file.Path.of(publicKeyPath), StandardCharsets.UTF_8);

        if (publicKey != null && !publicKey.isBlank()) {
            publicKeyK = parsePublicKey(publicKey);
        }
    }


    public Jws<Claims> parseWithPublicKey(String token) {
        return Jwts.parser().setSigningKey(publicKeyK).build().parseClaimsJws(
                token);
    }


    public JwtUserInfo parseTokenAuto(String token) {
        Jws<Claims> parsed = parseWithPublicKey(token);
        return toUserInfo(parsed);
    }

    public boolean validateJwtToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(publicKeyK)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException ex) {
            return false;
        }
    }

//    private PublicKey parsePublicKey(String pem) throws Exception {
//        pem = pem.replaceAll("-----BEGIN (.*)-----", "")
//                .replaceAll("-----END (.*)----", "")
//                .replaceAll("\\s", "");
//        byte[] bytes = java.util.Base64.getDecoder().decode(pem);
//        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        return kf.generatePublic(ks);
//    }


    private PublicKey parsePublicKey(String key) throws Exception {
        String publicKeyPEM = key
                .replace("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .trim();
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(keySpec);
    }


    public JwtUserInfo toUserInfo(Jws<Claims> parsed) {
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
        return new JwtUserInfo(userId, email, tenant, roles, emailVerified, enabled,
                issued, expires);
    }
}




