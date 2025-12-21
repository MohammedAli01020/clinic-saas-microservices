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


////


//@Service
//@RequiredArgsConstructor
//public class AuthService {
//
//    private final UserRepository userRepo;
//    private final RoleRepository roleRepo;
//    private final RefreshTokenRepository refreshRepo;
//    private final ProcessedEventRepository processedRepo;
//    private final PasswordEncoder passwordEncoder;
//    private final AuthenticationManager authManager;
//    private final JwtService jwtService;
//    private final KafkaTemplate<String, Object> kafkaTemplate;
//
//
//
//    @Transactional
//    public void signup(SignupRequest req) {
//        if (userRepo.findByEmail(req.getEmail()).isPresent()) throw new IllegalArgumentException("Email used");
//        User u = User.builder()
//                .email(req.getEmail())
//                .passwordHash(passwordEncoder.encode(req.getPassword()))
//                .tenantId(req.getTenantId())
//                .enabled(false)
//                .emailVerified(false)
//                .build();
//        // assign default role if exists
//
//        roleRepo.findByTenantId(req.getTenantId())
//                .stream()
//                .filter(r -> r.getName().equals("PATIENT"))
//                .findFirst()
//                .ifPresent(u::setRole);
//
//        userRepo.save(u);
//        // generate verification token and send event
//        String token = jwtService.generateEmailVerificationToken(u.getId().toString()); // reuse refresh generation for verification token (or create separate short token)
//        kafkaTemplate.send("email-verification", new EventModels.EmailVerificationEvent(u.getEmail(), token, u.getTenantId(), Instant.now()));
//    }
//
//    public LoginResponse login(LoginRequest req, String device, String ip) {
//        authManager.authenticate(new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword()));
//        User user = userRepo.findByEmail(req.getEmail()).orElseThrow();
//
////        List<String> roles = new ArrayList<>();
////        user.getRoles().forEach(r -> roles.add(r.getName()));
//
//        List<String> permissions = extractPermissions(user);
//
//        String access = jwtService.generateAccessToken(
//                user.getId().toString(),
//                user.getTenantId(),
//                user.getRole().getName(),
//                permissions);
//
//        String refresh = jwtService.generateRefreshToken(user.getId().toString());
//        // hash refresh
//        String hash = sha256(refresh);
//        RefreshToken rt = RefreshToken.builder()
//                .tokenHash(hash)
//                .user(user)
//                .device(device)
//                .ip(ip)
//                .createdAt(Instant.now())
//                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshExpirySeconds()))
//                .revoked(false)
//                .build();
//        refreshRepo.save(rt);
//        return new LoginResponse(access, refresh, user.getTenantId());
//    }
//
//    @Transactional
//    public LoginResponse refresh(String refreshTokenRaw) {
//        // verify signature
//        var decoded= jwtService.verify(refreshTokenRaw);
//        // ✅ check token type
//        if (!"refresh".equals(decoded.getClaim("type").asString())) {
//            throw new IllegalArgumentException("Not a refresh token");
//        }
//
//        String hash = sha256(refreshTokenRaw);
//        RefreshToken stored = refreshRepo.findByTokenHash(hash).orElseThrow(() -> new IllegalArgumentException("Invalid refresh"));
//        if (stored.isRevoked() || stored.getExpiresAt().isBefore(Instant.now()))
//            throw new IllegalArgumentException("Refresh expired or revoked");
//        User user = stored.getUser();
//
//        List<String> permissions = extractPermissions(user);
//
//        String access = jwtService.generateAccessToken(user.getId().toString(), user.getTenantId(), user.getRole().getName(), permissions);
//        // rotate refresh token -> issue new and revoke old
//        String newRefresh = jwtService.generateRefreshToken(user.getId().toString());
//        String newHash = sha256(newRefresh);
//        stored.setRevoked(true);
//        refreshRepo.save(stored);
//        RefreshToken rt = RefreshToken.builder()
//                .tokenHash(newHash)
//                .user(user)
//                .device(stored.getDevice())
//                .ip(stored.getIp())
//                .createdAt(Instant.now())
//                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshExpirySeconds()))
//                .revoked(false)
//                .build();
//        refreshRepo.save(rt);
//        return new LoginResponse(access, newRefresh, user.getTenantId());
//    }
//
//    @Transactional
//    public void logout(String refreshTokenRaw) {
//        String hash = sha256(refreshTokenRaw);
//        refreshRepo.findByTokenHash(hash).ifPresent(rt -> {
//            rt.setRevoked(true);
//            refreshRepo.save(rt);
//        });
//    }
//
//
//
//
//    @Transactional
//    public boolean verifyEmail(String token) {
//        try {
//            var decoded = jwtService.verify(token);
////            var decoded = jwtService.decode(token);
//
//            if (!"email_verification".equals(decoded.getClaim("type").asString())) {
//                throw new IllegalArgumentException("Invalid token type");
//            }
//
//            String userId = decoded.getSubject();
//            User u = userRepo.findById(Long.valueOf(userId)).orElseThrow();
//            u.setEmailVerified(true);
//            u.setEnabled(true);
//            userRepo.save(u);
//            return true;
//        } catch (Exception e) {
//            return false;
//        }
//    }
//
//    // used by onboarding listener
//    @Transactional
//    public void createAdminFromTenant(String tenantId, String ownerEmail, String correlationId) {
//        String eventId = "tenant-created::" + tenantId;
//        if (processedRepo.existsByEventId(eventId)) return;
//        Optional<User> ex = userRepo.findByEmail(ownerEmail);
//        if (ex.isPresent()) {
//            User u = ex.get();
//            u.setTenantId(tenantId);
//            userRepo.save(u);
//        } else {
//            User u = User.builder()
//                    .email(ownerEmail)
//                    .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
//                    .tenantId(tenantId)
//                    .enabled(false)
//                    .emailVerified(false)
//                    .build();
//            userRepo.save(u);
//        }
//        processedRepo.save(ProcessedEvent.builder().eventId(eventId).topic("tenant-created").build());
//    }
//
//    private String sha256(String input) {
//        try {
//            MessageDigest md = MessageDigest.getInstance("SHA-256");
//            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
//            return HexFormat.of().formatHex(hash);
//        } catch (NoSuchAlgorithmException ex) {
//            throw new RuntimeException("SHA-256 not supported", ex);
//        }
//    }
//
//
//    private List<String> extractPermissions(User user) {
//        if (user.getRole() == null || user.getRole().getPermissions() == null) {
//            return List.of();
//        }
//
//        return user.getRole()
//                .getPermissions()
//                .stream()
//                .map(Permission::getName)
//                .toList();
//    }
//
//}





