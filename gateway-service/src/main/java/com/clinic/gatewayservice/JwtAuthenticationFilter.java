package com.clinic.gatewayservice;

import com.clinic.sharedlib.jwt.CurrentUser;
import com.clinic.sharedlib.util.JsonUtils;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@Order(-1)
public class JwtAuthenticationFilter implements GlobalFilter {

    private final JwtUtils jwtUtil;

    public JwtAuthenticationFilter(JwtUtils jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // Public paths
        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }


        // استخراج الـ token من Header أو Cookie
        String token = extractToken(exchange);
        if (token == null || !jwtUtil.validateJwtToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        if (!jwtUtil.validateJwtToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Pass current user info in headers to downstream services
        CurrentUser user = jwtUtil.parseTokenAuto(token);

        // تحقق من type
        String tokenType = jwtUtil.getClaim(token, "type"); // هتحتاج تضيف method في JwtUtils
        if (!"access".equals(tokenType)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }


        try {
            String userInfoString = JsonUtils.toJson(user);
            exchange.getRequest().mutate()
                    .header("X-Current-User", userInfoString)
                    .build();

        } catch (RuntimeException e) {
            throw new RuntimeException("JsonProcessingException");
        }


        return chain.filter(exchange);
    }

    private boolean isPublicPath(String path) {
        return path.startsWith("/api/auth/login") || path.startsWith("/api/auth/signup") ||
                path.startsWith("/api/auth/refresh") || path.startsWith("/api/auth/verify") ||
                path.startsWith("/api/auth/welcome") ||
                path.startsWith("/health") || path.startsWith("/actuator/health");
    }


    private String extractToken(ServerWebExchange exchange) {
        List<String> authHeaders = exchange.getRequest().getHeaders().getOrEmpty("Authorization");
        if (!authHeaders.isEmpty() && authHeaders.get(0).startsWith("Bearer ")) {
            return authHeaders.get(0).substring(7);
        }

        // البحث في Cookies
        if (!exchange.getRequest().getCookies().isEmpty()) {
            HttpCookie cookie = exchange.getRequest().getCookies().getFirst("access_token");
            if (cookie != null) {
                return cookie.getValue();
            }
        }

        return null;
    }
}
