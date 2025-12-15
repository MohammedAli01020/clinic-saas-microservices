package com.clinic.sharedlib.tenant;

import com.clinic.sharedlib.jwt.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;

    public JwtAuthenticationFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

//        try {
//            String token = parseJwt(request);
//            if (token != null && jwtUtils.validateJwtToken(token)) {
//                // استدعاء JWTUserInfo من shared lib
//                var userInfo = jwtUtils.parseTokenAuto(token , "dkfrl");
//
//                // وضعه في TenantContext للوصول لاحقًا في أي service
//                UserContext.setUser(userInfo);
//
//                // يمكنك إنشاء Authentication لو تريد استخدام Spring Security
//                var authentication = jwtUtils.buildAuthentication(userInfo);
//                authentication.setDetails(Map.of(
//                        "ip", request.getRemoteAddr(),
//                        "tenantId", userInfo.getTenantId()
//                ));
//                // هنا ممكن تحط Authentication في SecurityContext لو تحتاج
//                // SecurityContextHolder.getContext().setAuthentication(authentication);
//            }
//        } catch (Exception e) {
//            logger.error("Cannot set user authentication: {}", e.getMessage());
//        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        // نبحث في Header أولًا
        String headerAuth = request.getHeader("Authorization");
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        // لو مش موجود في Header، نبحث في Cookie
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("access_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }
}