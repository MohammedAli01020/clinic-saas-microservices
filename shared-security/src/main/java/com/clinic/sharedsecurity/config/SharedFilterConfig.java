package com.clinic.sharedsecurity.config;

import com.clinic.sharedinternaltokengen.InternalTokenVerifier;
import com.clinic.sharedsecurity.filter.JwtAuthenticationFilter;
import com.clinic.sharedsecurity.filter.HibernateTenantFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SharedFilterConfig {

    // Bean للـ InternalTokenVerifier
    @Bean
    public InternalTokenVerifier internalTokenVerifier() {
        return new InternalTokenVerifier(); // عدل حسب constructor بتاعك
    }

    @Bean
    public JwtAuthenticationFilter currentUserContextFilterInstance(InternalTokenVerifier verifier) {
        return new JwtAuthenticationFilter(verifier);
    }

    @Bean
    public HibernateTenantFilter hibernateTenantFilterInstance() {
        return new HibernateTenantFilter();
    }


    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> currentUserFilter(JwtAuthenticationFilter filter) {
        FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(filter);
        registrationBean.setOrder(40); // ترتيب نسبي
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean<HibernateTenantFilter> hibernateTenantFilter(HibernateTenantFilter filter) {
        FilterRegistrationBean<HibernateTenantFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(filter);
        registrationBean.setOrder(45);
        return registrationBean;
    }
}
