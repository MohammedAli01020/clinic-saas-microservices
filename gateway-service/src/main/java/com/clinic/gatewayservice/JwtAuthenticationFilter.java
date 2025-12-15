package com.clinic.gatewayservice;

import com.clinic.sharedlib.jwt.JwtUserInfo;
import com.clinic.sharedlib.jwt.JwtUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
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

        List<String> authHeaders = exchange.getRequest().getHeaders().getOrEmpty("Authorization");
        if (authHeaders.isEmpty() || !authHeaders.get(0).startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeaders.get(0).substring(7);
        if (!jwtUtil.validateJwtToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Pass current user info in headers to downstream services
        JwtUserInfo user = jwtUtil.parseTokenAuto(token);

        try {
            String userInfoString = new ObjectMapper().writeValueAsString(user);
            exchange.getRequest().mutate()
                    .header("current-user", userInfoString)
                    .build();

        } catch (JsonProcessingException e) {
            throw new RuntimeException("JsonProcessingException");
        }


        return chain.filter(exchange);
    }

    private boolean isPublicPath(String path) {
        return path.startsWith("api/auth/login") || path.startsWith("api/auth/signup") ||
                path.startsWith("api/auth/refresh") || path.startsWith("api/auth/verify") ||
                path.startsWith("api/auth/welcome") ||
                path.startsWith("/health") || path.startsWith("/actuator/health");
    }

}
