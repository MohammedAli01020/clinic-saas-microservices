package com.clinic.gatewayservice;

import com.clinic.sharedinternaltokengen.InternalTokenGenerator;
import com.clinic.sharedsecurityjwt.UserPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
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
@Order(-1)
@Slf4j
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtUtils jwtUtils;
    private final InternalTokenGenerator internalTokenGenerator;

    public JwtAuthenticationFilter(JwtUtils jwtUtils,
                                   InternalTokenGenerator internalTokenGenerator) {
        this.jwtUtils = jwtUtils;
        this.internalTokenGenerator = internalTokenGenerator;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();

        log.info("JwtAuthenticationFilter triggered for path: {}", path);

        String serviceName = "";
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        if (route != null) {
            serviceName = route.getId();
        }

        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        String token = extractToken(exchange);

        log.info("token: " + token);

        if (token == null || !jwtUtils.validateJwtToken(token)) {
            log.info("isNotValidToken");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        UserPrincipal user = jwtUtils.parseTokenAuto(token);


        log.info("UserPrincipal: " + user.toString());

        String tokenType = jwtUtils.getClaim(token, "tokenType");
        if (!"access".equals(tokenType)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // 🔐 Generate internal JWT
        String internalJwt = internalTokenGenerator.generate(serviceName, user);

        log.info("internalJwt: " + internalJwt);

        ServerWebExchange mutated = exchange.mutate()
                .request(r -> r.header("X-Internal-Token", internalJwt))
                .build();

        return chain.filter(mutated);
    }

    private boolean isPublicPath(String path) {
        return path.startsWith("/api/auth/login") || path.startsWith("/api/auth/signup") ||
                path.startsWith("/api/auth/refresh") || path.startsWith("/api/auth/verify") ||
                path.startsWith("/api/auth/welcome") ||
                path.startsWith("/health") || path.startsWith("/actuator/health");
    }


    private String extractToken(ServerWebExchange exchange) {
        log.info("headers: " + exchange.getRequest().getHeaders());
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
