package com.clinic.authservice.service;


import com.clinic.authservice.domain.ProcessedEvent;
import com.clinic.authservice.domain.RefreshToken;
import com.clinic.authservice.domain.User;
import com.clinic.authservice.dto.LoginRequest;
import com.clinic.authservice.dto.LoginResponse;
import com.clinic.authservice.dto.SignupRequest;
import com.clinic.authservice.repository.ProcessedEventRepository;
import com.clinic.authservice.repository.RefreshTokenRepository;
import com.clinic.authservice.repository.RoleRepository;
import com.clinic.authservice.repository.UserRepository;
import com.clinic.authservice.security.JwtService;
import com.clinic.sharedlib.kafka.EventModels;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.authentication.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.time.Instant;
import java.util.*;
import java.security.MessageDigest;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final RefreshTokenRepository refreshRepo;
    private final ProcessedEventRepository processedRepo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final KafkaTemplate<String, Object> kafkaTemplate;



    @Transactional
    public void signup(SignupRequest req) {
        if (userRepo.findByEmail(req.getEmail()).isPresent()) throw new IllegalArgumentException("Email used");
        User u = User.builder()
                .email(req.getEmail())
                .passwordHash(passwordEncoder.encode(req.getPassword()))
                .tenantId(req.getTenantId())
                .enabled(false)
                .emailVerified(false)
                .build();
        // assign default role if exists
        roleRepo.findByTenantId(req.getTenantId()).stream().filter(r -> r.getName().equals("PATIENT")).findFirst().ifPresent(u.getRoles()::add);
        userRepo.save(u);
        // generate verification token and send event
        String token = jwtService.generateRefreshToken(u.getId().toString()); // reuse refresh generation for verification token (or create separate short token)
//        kafkaTemplate.send("email-verification", new EventModels.EmailVerificationEvent(u.getEmail(), token, u.getTenantId(), Instant.now()));
    }

    public LoginResponse login(LoginRequest req, String device, String ip) {
        authManager.authenticate(new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword()));
        User user = userRepo.findByEmail(req.getEmail()).orElseThrow();
        List<String> roles = new ArrayList<>();
        user.getRoles().forEach(r -> roles.add(r.getName()));
        String access = jwtService.generateAccessToken(user.getId().toString(), user.getTenantId(), roles);
        String refresh = jwtService.generateRefreshToken(user.getId().toString());
        // hash refresh
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
        return new LoginResponse(access, refresh, user.getTenantId());
    }

    @Transactional
    public LoginResponse refresh(String refreshTokenRaw) {
        // verify signature
        jwtService.verify(refreshTokenRaw);
        String hash = sha256(refreshTokenRaw);
        RefreshToken stored = refreshRepo.findByTokenHash(hash).orElseThrow(() -> new IllegalArgumentException("Invalid refresh"));
        if (stored.isRevoked() || stored.getExpiresAt().isBefore(Instant.now()))
            throw new IllegalArgumentException("Refresh expired or revoked");
        User user = stored.getUser();
        List<String> roles = new ArrayList<>();
        user.getRoles().forEach(r -> roles.add(r.getName()));
        String access = jwtService.generateAccessToken(user.getId().toString(), user.getTenantId(), roles);
        // rotate refresh token -> issue new and revoke old
        String newRefresh = jwtService.generateRefreshToken(user.getId().toString());
        String newHash = sha256(newRefresh);
        stored.setRevoked(true);
        refreshRepo.save(stored);
        RefreshToken rt = RefreshToken.builder()
                .tokenHash(newHash)
                .user(user)
                .device(stored.getDevice())
                .ip(stored.getIp())
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshExpirySeconds()))
                .revoked(false)
                .build();
        refreshRepo.save(rt);
        return new LoginResponse(access, newRefresh, user.getTenantId());
    }

    @Transactional
    public void logout(String refreshTokenRaw) {
        String hash = sha256(refreshTokenRaw);
        refreshRepo.findByTokenHash(hash).ifPresent(rt -> {
            rt.setRevoked(true);
            refreshRepo.save(rt);
        });
    }

    @Transactional
    public boolean verifyEmail(String token) {
        try {
            jwtService.verify(token);
            var decoded = jwtService.decode(token);
            String userId = decoded.getSubject();
            User u = userRepo.findById(Long.valueOf(userId)).orElseThrow();
            u.setEmailVerified(true);
            u.setEnabled(true);
            userRepo.save(u);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // used by onboarding listener
    @Transactional
    public void createAdminFromTenant(String tenantId, String ownerEmail, String correlationId) {
        String eventId = "tenant-created::" + tenantId;
        if (processedRepo.existsByEventId(eventId)) return;
        Optional<User> ex = userRepo.findByEmail(ownerEmail);
        if (ex.isPresent()) {
            User u = ex.get();
            u.setTenantId(tenantId);
            userRepo.save(u);
        } else {
            User u = User.builder()
                    .email(ownerEmail)
                    .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
                    .tenantId(tenantId)
                    .enabled(false)
                    .emailVerified(false)
                    .build();
            userRepo.save(u);
        }
        processedRepo.save(ProcessedEvent.builder().eventId(eventId).topic("tenant-created").build());
    }

    private String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : h) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}

