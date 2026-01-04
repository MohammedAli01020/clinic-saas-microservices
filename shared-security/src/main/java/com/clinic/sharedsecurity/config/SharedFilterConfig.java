package com.clinic.sharedsecurity.config;

import com.clinic.sharedinternaltokengen.InternalTokenVerifier;
import com.clinic.sharedsecurity.filter.JwtAuthenticationFilter;
import com.clinic.sharedsecurity.filter.HibernateTenantFilter;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.PersistenceContext;
import org.hibernate.SessionFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.orm.hibernate5.support.OpenSessionInViewFilter;
import org.springframework.orm.jpa.support.OpenEntityManagerInViewFilter;

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


    @PersistenceContext
    private EntityManager entityManager;

    @Bean
    public HibernateTenantFilter hibernateTenantFilterInstance() {
        return new HibernateTenantFilter(entityManager);
    }



    @Bean
    public FilterRegistrationBean<OpenEntityManagerInViewFilter> openEntityManagerInViewFilter() {
        FilterRegistrationBean<OpenEntityManagerInViewFilter> bean = new FilterRegistrationBean<>();
        bean.setFilter(new OpenEntityManagerInViewFilter());
        bean.setOrder(30);
        return bean;
    }


//    @Bean
//    public FilterRegistrationBean<JwtAuthenticationFilter> currentUserFilter(JwtAuthenticationFilter filter) {
//        FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
//        registrationBean.setFilter(filter);
//        registrationBean.setOrder(40); // ترتيب نسبي
//        return registrationBean;
//    }
//
//    @Bean
//    public FilterRegistrationBean<HibernateTenantFilter> hibernateTenantFilter(HibernateTenantFilter filter) {
//        FilterRegistrationBean<HibernateTenantFilter> registrationBean = new FilterRegistrationBean<>();
//        registrationBean.setFilter(filter);
//        registrationBean.setOrder(45);
//        return registrationBean;
//    }
}
