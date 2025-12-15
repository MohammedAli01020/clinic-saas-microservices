package com.clinic.authservice.controller;



import com.clinic.authservice.dto.LoginRequest;
import com.clinic.authservice.dto.LoginResponse;
import com.clinic.authservice.dto.SignupRequest;
import com.clinic.authservice.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final long refreshMaxAgeSec = Duration.ofDays(30).getSeconds(); // sync with JWT config or inject

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest req) {
        authService.signup(req);
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest req, HttpServletResponse resp, HttpServletRequest request) {
        String device = request.getHeader("User-Agent");
        String ip = request.getRemoteAddr();
        var res = authService.login(req, device, ip);
        // set HttpOnly secure cookie for refresh token
        ResponseCookie cookie = ResponseCookie.from("refresh_token", res.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/api/auth/refresh")
                .maxAge(refreshMaxAgeSec)
                .sameSite("Strict")
                .build();
        resp.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        // return access token in body
        return ResponseEntity.ok(new LoginResponse(res.getAccessToken(), null, res.getTenantId()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@CookieValue(name = "refresh_token", required = false) String refreshCookie, HttpServletResponse resp) {
        if (refreshCookie == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        var res = authService.refresh(refreshCookie);
        // set rotated cookie
        ResponseCookie cookie = ResponseCookie.from("refresh_token", res.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/api/auth/refresh")
                .maxAge(refreshMaxAgeSec)
                .sameSite("Strict")
                .build();
        resp.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok(new LoginResponse(res.getAccessToken(), null, res.getTenantId()));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@CookieValue(name="refresh_token", required=false) String refreshCookie, HttpServletResponse resp) {
        if (refreshCookie != null) authService.logout(refreshCookie);
        // clear cookie
        ResponseCookie cookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(true).secure(true).path("/api/auth/refresh").maxAge(0).build();
        resp.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/verify")
    public ResponseEntity<?> verify(@RequestParam("token") String token) {
        boolean ok = authService.verifyEmail(token);
        return ok ? ResponseEntity.ok().build() : ResponseEntity.badRequest().build();
    }
}
