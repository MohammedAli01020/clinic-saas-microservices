package com.clinic.gatewayservice;

import com.clinic.sharedinternaltokengen.InternalTokenGenerator;
import com.clinic.sharedsecurityjwt.UserPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@Slf4j
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtils jwtUtils;
    private final InternalTokenGenerator internalTokenGenerator;

    public JwtAuthenticationFilter(JwtUtils jwtUtils, InternalTokenGenerator internalTokenGenerator) {
        this.jwtUtils = jwtUtils;
        this.internalTokenGenerator = internalTokenGenerator;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        String token = extractToken(exchange);
        if (!isValidToken(token) || !"access".equals(jwtUtils.getClaim(token, "tokenType"))) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        UserPrincipal user = getUserFromToken(token);

        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        String serviceName = route != null ? route.getId() : "unknown-service"; // هيتملأ بعد كده

        log.info("Resolved serviceName: {}", serviceName);

        String internalJwt = internalTokenGenerator.generate(serviceName, user);

        ServerWebExchange mutated = exchange.mutate()
                .request(r -> r.header("X-Internal-Token", internalJwt))
                .build();

        return chain.filter(mutated);
    }

    @Override
    public int getOrder() {
        // لازم يكون بعد تحديد ال route
        return 1;
    }

    private boolean isPublicPath(String path) {
        return path.startsWith("/api/auth/login") ||
                path.startsWith("/api/auth/signup") ||
                path.startsWith("/api/auth/refresh") ||
                path.startsWith("/api/auth/verify") ||
                path.startsWith("/api/auth/welcome") ||
                path.startsWith("/health") ||
                path.startsWith("/actuator/health");
    }

    private boolean isValidToken(String token) {
        return token != null && jwtUtils.validateJwtToken(token);
    }

    private UserPrincipal getUserFromToken(String token) {
        return jwtUtils.parseTokenAuto(token);
    }

    private String extractToken(ServerWebExchange exchange) {
        // 1️⃣ جرب Authorization header
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
            return authHeader.substring(7).trim();
        }

        // 2️⃣ جرب الكوكيز
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst("access_token");
        if (cookie != null) {
            return cookie.getValue();
        }

        // 3️⃣ مفيش توكن
        return null;
    }

}
