package com.clinic.sharedinternaltokengen;


import com.clinic.sharedsecurityjwt.SecurityPrincipal;
import com.clinic.sharedsecurityjwt.ServicePrincipal;
import com.clinic.sharedsecurityjwt.UserPrincipal;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

@Component
public class InternalTokenGenerator {

    @Value("${app.jwt.internal-private-key-pem}")
    private String internalPrivateKeyPem;


    @Value("${spring.application.name}")
    private String currentServiceName;

    private PrivateKey privateKey;

    private final long expirationMs = 2 * 60 * 1000; // 2 minutes

    @PostConstruct
    public void init() {

        try {
            privateKey = parsePrivateKey(internalPrivateKeyPem);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize JWT Service", e);
        }
    }

    public String generate(String targetService, SecurityPrincipal principal) {
        Date now = new Date();
        Date exp = new Date(System.currentTimeMillis() + expirationMs);

        var builder = Jwts.builder()
                .setSubject(principal.sub())
                .setIssuer(currentServiceName)
                .setIssuedAt(now)
                .setExpiration(exp)
                .claim("principalType", principal.principalType().name())
                .claim("aud", List.of(targetService));

        if (principal instanceof ServicePrincipal service) {
            builder.claim("tenantId", service.tenantId())
                    .claim("scopes", service.getScopes());


        } else if (principal instanceof UserPrincipal user) {
            builder.claim("email", user.getEmail())
                    .claim("role", user.getRole())
                    .claim("permissions", user.getPermissions())
                    .claim("tenantId", user.tenantId())
                    .claim("isEnabled", user.getIsEnabled());
        }

        return builder.signWith(privateKey, SignatureAlgorithm.RS256).compact();
    }

    private PrivateKey parsePrivateKey(String key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(cleanPem(key));
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    private String cleanPem(String pem) {
        return pem
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\\s+", "");
    }
}
