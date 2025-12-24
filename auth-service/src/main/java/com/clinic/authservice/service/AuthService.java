package com.clinic.authservice.service;


import com.clinic.authservice.domain.RefreshToken;

import com.clinic.authservice.dto.LoginRequest;
import com.clinic.authservice.dto.LoginResponse;
import com.clinic.authservice.dto.SignupRequest;
import com.clinic.authservice.repository.AuthUserRepository;
import com.clinic.authservice.repository.RefreshTokenRepository;

import com.clinic.authservice.security.JwtService;

import com.clinic.authservice.utils.GoogleUserInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

import java.security.MessageDigest;


import com.clinic.authservice.domain.AuthUser;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthUserRepository userRepo;
    private final RefreshTokenRepository refreshRepo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final KafkaTemplate<String, Object> kafkaTemplate;


    // ----------------------
    // Signup (Local User)
    // ----------------------
    @Transactional
    public void signup(SignupRequest req) {
        if (userRepo.findByEmail(req.getEmail()).isPresent())
            throw new IllegalArgumentException("Email used");

//        AuthUser u = AuthUser.builder()
//                .email(req.getEmail())
//                .passwordHash(passwordEncoder.encode(req.getPassword()))
//                .tenantId(req.getTenantId())
//                .enabled(false)
//                .emailVerified(false)
//                .build();

//        userRepo.save(u);
//
//        // Generate email verification token
//        String token = jwtService.generateEmailVerificationToken(u.getId().toString());
        // TODO: send token via Kafka/email
    }

    // ----------------------
    // Login (Local)
    // ----------------------
    public LoginResponse login(LoginRequest req, String device, String ip) {

        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
        );

        AuthUser user = userRepo.findByEmail(req.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));



        // Extract permissions from UserManagement or default empty
        List<String> permissions = List.of(); // placeholder

        String access = jwtService.generateAccessToken(
                user.getId().toString(),
                user.getTenantId(),
                user.isEnabled(),
                "USER",        // placeholder role
                permissions
        );

        String refresh = jwtService.generateRefreshToken(user.getId().toString());
        saveRefreshToken(user, refresh, device, ip);

        return new LoginResponse(access, refresh, user.getTenantId());
    }

    // ----------------------
    // Login (Google)
    // ----------------------
//    @Transactional
//    public LoginResponse socialLogin(SocialLoginRequest req, String device, String ip) {
//        // Verify Google token
//        var info = jwtService.verifyGoogleToken(req.getIdToken());
//
//        AuthUser user = userRepo.findByEmail(info.getEmail())
//                .orElseGet(() -> createGoogleUser(info));
//
//        List<String> permissions = List.of(); // placeholder
//
//        String access = jwtService.generateAccessToken(
//                user.getId().toString(),
//                user.getTenantId(),
//                "USER",  // placeholder role
//                permissions
//        );
//
//        String refresh = jwtService.generateRefreshToken(user.getId().toString());
//        saveRefreshToken(user, refresh, device, ip);
//
//        return new LoginResponse(access, refresh, user.getTenantId());
//    }

    // ----------------------
    // Refresh Token
    // ----------------------
    @Transactional
    public LoginResponse refresh(String refreshTokenRaw) {
        var decoded = jwtService.verify(refreshTokenRaw);
        if (!"refresh".equals(decoded.getClaim("type").asString()))
            throw new IllegalArgumentException("Not a refresh token");

        String hash = sha256(refreshTokenRaw);
        RefreshToken stored = refreshRepo.findByTokenHash(hash)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));

        if (stored.isRevoked() || stored.getExpiresAt().isBefore(Instant.now()))
            throw new IllegalArgumentException("Refresh expired or revoked");

        AuthUser user = stored.getUser();
        List<String> permissions = List.of(); // placeholder

        String access = jwtService.generateAccessToken(
                user.getId().toString(),
                user.getTenantId(),
                user.isEnabled(),
                "USER",
                permissions
        );

        // Rotate refresh token
        stored.setRevoked(true);
        refreshRepo.save(stored);

        String newRefresh = jwtService.generateRefreshToken(user.getId().toString());
        saveRefreshToken(user, newRefresh, stored.getDevice(), stored.getIp());

        return new LoginResponse(access, newRefresh, user.getTenantId());
    }

    // ----------------------
    // Logout
    // ----------------------
    @Transactional
    public void logout(String refreshTokenRaw) {
        String hash = sha256(refreshTokenRaw);
        refreshRepo.findByTokenHash(hash).ifPresent(rt -> {
            rt.setRevoked(true);
            refreshRepo.save(rt);
        });
    }

    // ----------------------
    // Email Verification
    // ----------------------
    @Transactional
    public boolean verifyEmail(String token) {
        try {
            var decoded = jwtService.verify(token);
            if (!"email_verification".equals(decoded.getClaim("type").asString()))
                throw new IllegalArgumentException("Invalid token type");

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
                .device(device)
                .ip(ip)
                .createdAt(Instant.now())
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

}






