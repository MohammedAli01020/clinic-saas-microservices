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

        log.info("privateKey: " + privateKey);


//        privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDFnUDEZlcXc3TEHk7Jmfs/xDECiC+J8U0XIEfWL29Kroe3A/PVRAVrjOHJTGXHxrNiLmwOfv3TgNsEn/4tv2XXYRfncxmMeaQ0y7z51moXChYsEo9TjJvmNYf+ZRzBJ6CcNvOWOW36XehgWfX3QQ/VIGShDBy3rsYIRT2AQVBE74mUYb2vHkw7PeZYo6LD5M0jvUJ6S47Qdw2dQc76eepnnXJ/pVThXmmcHzhaysGJ/x1WbDQuLoyp+UYRzvQ9U/fVtQvsJnKulswaIn9mMcOYwzECwve9AVW5j0o4KbmlUa728O6dRc2TKEV03ykw3z/c6ELci+tfVuRNCtB9Q4inAgMBAAECggEATFWDtLoBj136b11zur1fx9B9zAgWMPdEe5ftF+fn2hXT99avhCSL4XEgsJTxxftTxKvA8tKMMvyV3dH9qedCrDFlvfKAnnpIe1puC6YPAgpT6T9cHP52JDVubE7bjiNED8PMUS2q9Wj7/+gQMqvvtTiXlnwqxatd9MjmSlowawfcu7wcvtxelF39CA82hPv8v4wuEaOr4qxYxT1+n2qLpzoKCQEt6iU4bf3XarkqH9i2wtCLWyfZwmBRIOhTAQzTXpYE9lJgbEliiONuDyjBzuql8ozAkDYSmn6KoIMRT9tLa6yZolDM+GX/Py6Ffp+sOpCdL4foeufqW0G6fPpCKQKBgQDi8Q6I4hlrs6eABldiInXoEKrYhpXKwEvLg+LCsK0cy5txsoz91I7+CYDr76wmG/USR7zH9J3cKfqzQJgr0o8W6IArcxav4Jek4x1JJyJpZG+jgoShiEb0cY+BjkQdGGc8h7i/dM6dAVcstC48f35Z28uBCMrQUhdhu49/UfXDzwKBgQDe6t8m1f9oKNlVppZPSAy9352lIF0mnCHRoNlndmD1frSLcQO972g4+7+9t4cj79AkxyWs2ytIiY9aOJVPK77P33mdgqO+OifWTEWaX4heGI2b+tlbwMNPpQLpkujVh4jyF+3eySRSJ+ZoNXyFO0yyBjh+LIJ+p9EgLE50wKarqQKBgBgKz65ivayyULl4coN8AR+/vEnKIE5lhuIdq8VScFSPoX0vHE672RZCrXzRXFyBM7pnDTHl0V+EtwGMg1KJMQ2NPh7cR3gEhCw8v1qDodqmgElDR4fRZyr4aOqhxseKUU2RV1o5JrZtcO3UfN196EXeyjV2V/4v5Dg/ZZlodm/zAoGACMTQdmSgoWZJ9laRPxkkdyueteop/+TQZ8CeDLXZZo7PZ1TQwt3yCZvNlRbtF/rNA0VaNAyDDV1r6C6loPGllePCkvGao1cCTim96y6q3Ji2qVYaysMwa6egD7QZuJyWRH+web0L0reDFsJT3aHRiIc6Hax+jaDoVw2nIGybodECgYEAgJpQTlDDwgTdg3ekSuEFZP/WVNBx/piHPXNhNVdAV1sH10NQk4MPA2rUz3ej3srPqAYU1rwSkQnKH0N6+9fHldH8Dzb72GhUeWLe1IBkeXf317TtO3AfaCRDDSTyn00SFpus1ECPOvwe3oBMKMMGiw02J7MXQrGHdAuEPmF1elk=";

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



    private PrivateKey parsePrivateKey(String key) throws Exception {

        try {
            String privateKeyPEM = key
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");


            byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);

            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (Exception e) {

            log.info("parsePrivateKey Exception" + e.getMessage());
        }

        return null;

    }

    public long getRefreshExpirySeconds() {
        return refreshExpDays * 24 * 3600;
    }

}
