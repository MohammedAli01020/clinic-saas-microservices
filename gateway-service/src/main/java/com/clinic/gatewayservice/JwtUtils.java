package com.clinic.gatewayservice;

import com.clinic.sharedsecurityjwt.PrincipalType;
import com.clinic.sharedsecurityjwt.UserPrincipal;
import io.jsonwebtoken.*;
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

    @Value("${security.jwt.public-key-pem}")
    private String publicKeyPem;

    private PublicKey publicKey;


    @PostConstruct
    public void init() throws Exception {

        if (publicKeyPem != null && !publicKeyPem.isBlank()) {
            publicKey = parsePublicKey(publicKeyPem);
        }
    }


    public Jws<Claims> parseWithPublicKey(String token) {

        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token);

    }


    public UserPrincipal parseTokenAuto(String token) {
        Jws<Claims> parsed = parseWithPublicKey(token);
        return toUserInfo(parsed);
    }

    public boolean validateJwtToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException ex) {

            throw new RuntimeException("validateJwtToken " + ex.getMessage());
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

    @SuppressWarnings("unchecked")
    private static Set<String> extractSet(Object claim) {
        if (claim instanceof Collection<?> collection) {
            return collection.stream()
                    .map(String::valueOf)
                    .collect(Collectors.toUnmodifiableSet());
        }
        return Set.of();
    }

    private static boolean isTrue(Claims claims, String key) {
        return Boolean.TRUE.equals(claims.get(key, Boolean.class));
    }


    public UserPrincipal toUserInfo(Jws<Claims> parsed) {
        Claims claims = parsed.getBody();

        return UserPrincipal.builder()
                .sub(claims.getSubject())
                .iss(claims.getIssuer())
                .email(claims.get("email", String.class))
                .tenantId(claims.get("tenantId", String.class))
                .role(claims.get("role", String.class))
                .permissions(extractSet(claims.get("permissions")))
                .isEnabled(isTrue(claims, "isEnabled"))
                .issuedAt(claims.getIssuedAt().toInstant())
                .expiresAt(claims.getExpiration().toInstant())
                .principalType(PrincipalType.USER)
                .build();

    }
}




