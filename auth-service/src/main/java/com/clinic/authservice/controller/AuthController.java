package com.clinic.authservice.controller;


import com.clinic.authservice.dto.LoginRequest;
import com.clinic.authservice.dto.SignupRequest;
import com.clinic.authservice.security.JwtService;
import com.clinic.authservice.service.AuthService;
import com.clinic.authservice.service.OnboardingService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;
    private final long refreshMaxAgeSec = Duration.ofDays(30).getSeconds();
    private final OnboardingService onboardingService;

    @PostMapping("/signup")
    public ResponseEntity<Map<String, Object>> signup(@RequestBody SignupRequest req) {

        onboardingService.onboardTenantAdmin(req.getEmail(),
                req.getPassword(), req.getFullName(), req.getTenantId());

//        authService.signup(req);

        return ResponseEntity.accepted().body(Map.of(
                "status", "success",
                "message", "Signup successful"
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest req,
                                                     HttpServletResponse resp,
                                                     HttpServletRequest request) {
        String device = request.getHeader("User-Agent");
        String ip = request.getRemoteAddr();
        var res = authService.login(req, device, ip);

        // set HttpOnly secure refresh cookie
        ResponseCookie cookie = ResponseCookie.from("refresh_token", res.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/api/auth")
                .maxAge(refreshMaxAgeSec)
                .sameSite("Strict")
                .build();

        resp.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        resp.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        resp.setHeader(HttpHeaders.PRAGMA, "no-cache");

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "accessToken", res.getAccessToken(),
                "tenantId", res.getTenantId()
        ));
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@CookieValue(name = "refresh_token", required = false) String refreshCookie,
                                                       HttpServletResponse resp) {
        if (refreshCookie == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "status", "error",
                    "message", "Missing refresh token"
            ));
        }

        var decoded = jwtService.verify(refreshCookie);
        if (!"refresh".equals(decoded.getClaim("type").asString())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "status", "error",
                    "message", "Invalid token type"
            ));
        }

        var res = authService.refresh(refreshCookie);

        ResponseCookie cookie = ResponseCookie.from("refresh_token", res.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/api/auth")
                .maxAge(refreshMaxAgeSec)
                .sameSite("Strict")
                .build();

        resp.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        resp.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        resp.setHeader(HttpHeaders.PRAGMA, "no-cache");

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "accessToken", res.getAccessToken(),
                "tenantId", res.getTenantId()
        ));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(@CookieValue(name = "refresh_token", required = false) String refreshCookie,
                                                      HttpServletResponse resp) {
        if (refreshCookie != null) authService.logout(refreshCookie);

        // clear cookie
        ResponseCookie cookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(true)
                .path("/api/auth")
                .maxAge(0)
                .sameSite("Strict")
                .build();

        resp.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        resp.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        resp.setHeader(HttpHeaders.PRAGMA, "no-cache");

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Logged out successfully"
        ));
    }

    @GetMapping("/verify")
    public ResponseEntity<Map<String, Object>> verify(@RequestParam("token") String token) {
        boolean verified = authService.verifyEmail(token);
        if (verified) {
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Email verified"
            ));
        } else {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", "Invalid or expired token"
            ));
        }
    }


}
