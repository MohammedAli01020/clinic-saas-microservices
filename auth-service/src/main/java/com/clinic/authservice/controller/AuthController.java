package com.clinic.authservice.controller;


import com.clinic.authservice.dto.LoginRequest;
import com.clinic.authservice.dto.SignupRequest;
import com.clinic.authservice.security.JwtService;
import com.clinic.authservice.service.AuthService;
import com.clinic.authservice.service.OnboardingService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
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
        setRefreshTokenCookie(resp, res.getRefreshToken());

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "accessToken", res.getAccessToken(),
                "refreshToken", res.getRefreshToken(),
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

        try {
            var res = authService.refresh(refreshCookie);
            setRefreshTokenCookie(resp, res.getRefreshToken());

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "accessToken", res.getAccessToken(),
                    "refreshToken", res.getRefreshToken(),
                    "tenantId", res.getTenantId()
            ));
        } catch (BadCredentialsException e) {
            log.warn("Refresh token failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "status", "error",
                    "message", e.getMessage()
            ));
        } catch (Exception e) {
            log.error("Unexpected error during refresh", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "status", "error",
                    "message", "Unexpected error"
            ));
        }
    }


    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(@CookieValue(name = "refresh_token", required = false) String refreshCookie,
                                                      HttpServletResponse resp) {
        if (refreshCookie != null) authService.logout(refreshCookie);

        // clear cookie
        clearRefreshTokenCookie(resp);

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


    private void setRefreshTokenCookie(HttpServletResponse resp, String refreshToken) {
        ResponseCookie cookie = ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(false)
                .path("/api/auth")
                .maxAge(refreshMaxAgeSec)
                .sameSite("Lax")
//                .sameSite("Strict")

                // TODO in the prod mode change to sameSite("Strict") and secure(true)
                .build();

        resp.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        resp.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        resp.setHeader(HttpHeaders.PRAGMA, "no-cache");
    }


    private void clearRefreshTokenCookie(HttpServletResponse resp) {
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
    }



}
