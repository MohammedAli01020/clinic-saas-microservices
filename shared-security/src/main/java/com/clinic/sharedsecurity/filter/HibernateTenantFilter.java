package com.clinic.sharedsecurity.filter;

import com.clinic.sharedsecurityjwt.CurrentUser;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class HibernateTenantFilter extends OncePerRequestFilter {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof CurrentUser user) {
            String tenantId = user.tenantId();

            Session session = entityManager.unwrap(Session.class);
            if (session != null) {
                session.enableFilter("tenantFilter").setParameter("tenantId", tenantId);
                session.enableFilter("deletedFilter");
            }

            log.debug("TenantFilter applied for tenantId={}", tenantId);

            try {
                filterChain.doFilter(request, response);
            } finally {
                // إغلاق الـ filters بعد الطلب
                if (session != null) {
                    session.disableFilter("tenantFilter");
                    session.disableFilter("deletedFilter");
                }
            }

        } else {
            log.debug("No authenticated user found, skipping tenantFilter and deletedFilter");
            filterChain.doFilter(request, response);
        }
    }
}
