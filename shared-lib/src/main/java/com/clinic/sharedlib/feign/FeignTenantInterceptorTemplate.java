package com.clinic.sharedlib.feign;


import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Template for Feign interceptor.
 * DO NOT annotate in shared-lib. Copy this class into each service and add @Component there.
 * <p>
 * This interceptor forwards:
 * - X-TENANT-ID header (from TenantContext)
 * - Authorization header (Bearer <token>) if available in SecurityContext (credentials)
 */
public class FeignTenantInterceptorTemplate implements RequestInterceptor {

    @Override
    public void apply(RequestTemplate template) {
//        String tenant = TenantContext.getTenantId();
//        if (tenant != null && !tenant.isBlank())
//            template.header("X-TENANT-ID", tenant);
//
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        if (auth != null && auth.getCredentials() instanceof String) {
//            String token = (String) auth.getCredentials();
//            if (token != null && !token.isBlank()) template.header("Authorization", "Bearer " + token);
//        }
    }
}