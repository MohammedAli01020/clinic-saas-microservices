package com.clinic.authservice.security;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.clinic.sharedlib.jwt.JwtUserInfo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;

@Component
public class JwtService {

    @Value("${app.jwt.private-key}")
    private String privateKey;

    @Value("${app.jwt.issuer:clinic-auth}")
    private String issuer;

    @Value("${app.jwt.access-exp-minutes:15}")
    private long accessExpMinutes;

    @Value("${app.jwt.refresh-exp-days:30}")
    private long refreshExpDays;

    private Algorithm algorithm;

    @PostConstruct
    public void init() throws Exception {

//        String pkPem = Files.readString(java.nio.file.Path.of(privateKeyPath), StandardCharsets.UTF_8);

        if (privateKey == null || privateKey.isBlank()) throw new IllegalStateException("Missing JWT private key");

        PrivateKey privateKeyValue = parsePrivateKey(privateKey);
        algorithm = Algorithm.RSA256(null, (RSAPrivateKey) privateKeyValue);

    }

    public String generateAccessToken(String subjectId, String tenantId, List<String> roles) {
        Instant now = Instant.now();
        return JWT.create()
                .withIssuer(issuer)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusSeconds(accessExpMinutes * 60)))
                .withSubject(subjectId)
                .withClaim("tenant", tenantId)
                .withClaim("roles", roles)
                .sign(algorithm);
    }

    public String generateRefreshToken(String subjectId) {
        Instant now = Instant.now();
        return JWT.create()
                .withIssuer(issuer)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusSeconds(refreshExpDays * 24 * 3600)))
                .withSubject(subjectId)
                .sign(algorithm);
    }

    public DecodedJWT decode(String token) {
        return JWT.decode(token);
    }

    public void verify(String token) {
        // verify signature (throws if invalid)
        JWT.require(algorithm).build().verify(token);
    }

//    private PrivateKey parsePrivateKey(String pem) throws Exception {
//        pem = pem.replaceAll("-----BEGIN (.*)-----", "")
//                .replaceAll("-----END (.*)----", "")
//                .replaceAll("\\s", "");
//        byte[] bytes = java.util.Base64.getDecoder().decode(pem);
//        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        return kf.generatePrivate(ks);
//    }


    private PrivateKey parsePrivateKey(String key) throws Exception {
        String privateKeyPEM = key
                .replace("\\n", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .trim();
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    public long getRefreshExpirySeconds() {
        return refreshExpDays * 24 * 3600;
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
