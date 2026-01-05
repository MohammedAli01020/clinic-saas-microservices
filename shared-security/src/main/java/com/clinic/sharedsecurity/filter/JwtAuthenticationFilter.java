package com.clinic.sharedsecurity.filter;

import com.clinic.sharedinternaltokengen.InternalTokenVerifier;
import com.clinic.sharedsecurity.context.TenantContext;
import com.clinic.sharedsecurityjwt.SecurityPrincipal;
import com.clinic.sharedsecurityjwt.ServicePrincipal;
import com.clinic.sharedsecurityjwt.UserPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final InternalTokenVerifier verifier;

    private final Set<String> publicEndpoints = Set.of(
            "/api/auth/login", "/api/auth/signup", "/api/auth/refresh",
            "/api/auth/verify", "/api/auth/welcome", "/actuator/health", "/health"
    );

    public JwtAuthenticationFilter(InternalTokenVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws IOException, ServletException {

        String path = request.getRequestURI();

        // endpoints عامة بدون token
        if (publicEndpoints.stream().anyMatch(path::startsWith)) {
            filterChain.doFilter(request, response);
            return;
        }

        String internalToken = request.getHeader("X-Internal-Token");

        if (internalToken == null || internalToken.isBlank()) {
            log.warn("Missing internal token from IP: {}", request.getRemoteAddr());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing internal token");
            return;
        }

        try {
            // التحقق من صلاحية Internal JWT وتحويله لـ SecurityPrincipal
            SecurityPrincipal principal = verifier.verify(internalToken);
            TenantContext.setTenantId(principal.tenantId());

            // بناء authorities بناء على نوع principal
            List<SimpleGrantedAuthority> authorities;
            if (principal instanceof UserPrincipal user) {
                authorities = user.getPermissions().stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                authorities.add(new SimpleGrantedAuthority("ROLE_" + user.getRole()));

            } else if (principal instanceof ServicePrincipal service) {
                authorities = service.getScopes().stream()
                        .map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
                        .collect(Collectors.toList());
            } else {
                authorities = List.of();
            }

            // إنشاء Authentication object
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(principal, null, authorities);
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // تعيين Authentication في SecurityContext
            SecurityContextHolder.getContext().setAuthentication(auth);

            // استكمال الفلترة
            filterChain.doFilter(request, response);

        } catch (Exception ex) {
            log.warn("Invalid internal token from IP {}: {}", request.getRemoteAddr(), ex.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid internal token");
        }
    }
}
