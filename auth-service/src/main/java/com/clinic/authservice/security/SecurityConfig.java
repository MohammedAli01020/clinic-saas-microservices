package com.clinic.authservice.security;

import com.clinic.authservice.repository.AuthUserRepository;
import com.clinic.sharedsecurity.filter.HibernateTenantFilter;
import com.clinic.sharedsecurity.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final AuthUserRepository authUserRepository;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final HibernateTenantFilter hibernateTenantFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authManager) throws Exception {


        http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)

                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(hibernateTenantFilter, JwtAuthenticationFilter.class)

                .authorizeHttpRequests(auth -> auth

                        .requestMatchers("/api/auth/welcome",
                                "/api/auth/login",
                                "/api/auth/signup",
                                "/api/auth/verify",
                                "/api/auth/refresh").permitAll()
                        .anyRequest().authenticated()
                );

        http.authenticationManager(authManager);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(customUserDetailService());
        authProvider.setPasswordEncoder(passwordEncoder());

        AuthenticationManagerBuilder authBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authBuilder.authenticationProvider(authProvider);

        return authBuilder.build();
    }


    @Bean
    public CustomUserDetailService customUserDetailService() {
        return new CustomUserDetailService(authUserRepository);
    }


}
