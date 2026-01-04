package com.clinic.authservice.service;

import com.clinic.authservice.client.UserManagementClient;
import com.clinic.authservice.domain.AuthUser;
import com.clinic.authservice.domain.RefreshToken;
import com.clinic.authservice.dto.LoginRequest;
import com.clinic.authservice.dto.LoginResponse;
import com.clinic.authservice.dto.SignupRequest;
import com.clinic.authservice.dto.UserRolesPermissionsDto;
import com.clinic.authservice.repository.AuthUserRepository;
import com.clinic.authservice.repository.RefreshTokenRepository;
import com.clinic.authservice.security.JwtService;
import com.clinic.authservice.utils.GoogleUserInfo;
import com.clinic.sharedinternaltokengen.InternalTokenGenerator;
import com.clinic.sharedsecurityjwt.PrincipalType;
import com.clinic.sharedsecurityjwt.ServicePrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthUserRepository userRepo;
    private final RefreshTokenRepository refreshRepo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final KafkaTemplate<String, Object> kafkaTemplate;

    private final InternalTokenGenerator internalTokenGenerator;
    private final UserManagementClient userManagementClient;

    // ----------------------
    // Signup (Local User)
    // ----------------------
    @Transactional
    public void signup(SignupRequest req) {
        if (userRepo.findByEmail(req.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already used");
        }

        // Uncomment to enable user creation & email verification
        /*
        AuthUser u = AuthUser.builder()
                .email(req.getEmail())
                .passwordHash(passwordEncoder.encode(req.getPassword()))
                .tenantId(req.getTenantId())
                .enabled(false)
                .emailVerified(false)
                .build();
        userRepo.save(u);

        String token = jwtService.generateEmailVerificationToken(u.getId().toString());
        // TODO: send token via Kafka/email
        */
    }

    // ----------------------
    // Login (Local)
    // ----------------------
    @Transactional
    public LoginResponse login(LoginRequest req, String device, String ip) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
        );

        AuthUser user = userRepo.findByEmail(req.getEmail())
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        UserRolesPermissionsDto rp = fetchUserRolesPermissions(user);
        String access = generateAccessToken(user, rp);

        String refresh = jwtService.generateRefreshToken(user.getId().toString(), user.getTenantId());
        saveRefreshToken(user, refresh, device, ip);

        return new LoginResponse(access, refresh, user.getTenantId());
    }


    // ----------------------
    // Refresh Token
    // ----------------------
    @Transactional
    public LoginResponse refresh(String refreshTokenRaw) {
        var decoded = jwtService.verify(refreshTokenRaw);

        log.info("decoded: " + decoded.getClaims().toString());
        if (!"refresh".equals(decoded.getClaim("tokenType").asString())) {
            throw new BadCredentialsException("Invalid token type");
        }

        String tenantId = decoded.getClaim("tenantId").asString();
        String hash = sha256(refreshTokenRaw);

        RefreshToken stored = refreshRepo.findByTokenHashAndTenantId(hash, tenantId)
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));

        if (stored.isRevoked() || stored.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token expired or revoked");
        }

        stored.setRevoked(true);
        refreshRepo.save(stored);

        AuthUser user = stored.getUser();
        UserRolesPermissionsDto rp = fetchUserRolesPermissions(user);
        String access = generateAccessToken(user, rp);

        String newRefresh = jwtService.generateRefreshToken(user.getId().toString(), user.getTenantId());
        saveRefreshToken(user, newRefresh, stored.getDevice(), stored.getIp());

        return new LoginResponse(access, newRefresh, user.getTenantId());
    }


    // ----------------------
    // Logout
    // ----------------------
    @Transactional
    public void logout(String refreshTokenRaw) {
        String hash = sha256(refreshTokenRaw);
        var decoded = jwtService.verify(refreshTokenRaw);
        String tenantId = decoded.getClaim("tenantId").asString();

        refreshRepo.findByTokenHashAndTenantId(hash, tenantId)
                .ifPresent(rt -> rt.setRevoked(true));
    }

    // ----------------------
    // Email Verification
    // ----------------------
    @Transactional
    public boolean verifyEmail(String token) {
        try {
            var decoded = jwtService.verify(token);
            if (!"email_verification".equals(decoded.getClaim("tokenType").asString())) {
                throw new BadCredentialsException("Invalid token type");
            }

            String userId = decoded.getSubject();
            AuthUser u = userRepo.findById(Long.valueOf(userId))
                    .orElseThrow();
            u.setEmailVerified(true);
            u.setEnabled(true);
            userRepo.save(u);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ----------------------
    // Helpers
    // ----------------------
    private AuthUser createGoogleUser(GoogleUserInfo info) {
        AuthUser user = AuthUser.builder()
                .email(info.getEmail())
                .provider(info.getProvider())
                .providerId(info.getSub())
                .emailVerified(info.isEmailVerified())
                .enabled(true)
                .build();
        return userRepo.save(user);
    }

    private void saveRefreshToken(AuthUser user, String refresh, String device, String ip) {
        String hash = sha256(refresh);

        RefreshToken rt = RefreshToken.builder()
                .tokenHash(hash)
                .user(user)
                .tenantId(user.getTenantId())
                .device(device)
                .ip(ip)
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshExpirySeconds()))
                .revoked(false)
                .build();

        refreshRepo.save(rt);
    }

    private String sha256(String input) {
        try {
            var md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not supported", e);
        }
    }

    private UserRolesPermissionsDto fetchUserRolesPermissions(AuthUser user) {
        String internalToken = internalTokenGenerator.generate(
                "user-management-service",
                ServicePrincipal.builder()
                        .sub("auth-service")
                        .principalType(PrincipalType.SERVICE)
                        .scopes(Set.of("USER_READ"))
                        .tenantId(user.getTenantId())
                        .build()
        );

        return userManagementClient.getRolesPermissions(
                user.getId().toString(),
                internalToken
        );
    }
    private String generateAccessToken(AuthUser user, UserRolesPermissionsDto rp) {
        return jwtService.generateAccessToken(
                user.getId().toString(),
                user.getEmail(),
                user.getTenantId(),
                user.isEnabled(),
                rp.role(),
                rp.permissions()
        );
    }

}
