package com.clinic.authservice.security;


import com.clinic.authservice.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class CustomerUserDetailsImpl implements UserDetails {

    private final User currentUser;

    public CustomerUserDetailsImpl(User currentUser) {
        this.currentUser = currentUser;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (currentUser.getRoles() == null) {
            return List.of();
        }
        return currentUser.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.toString()))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        // عادة الـ password لا يُخزن في UserInfo إذا جاي من JWT
        return currentUser.getPasswordHash();
    }

    @Override
    public String getUsername() {
        return currentUser.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return currentUser.isEnabled();
    }

    // إضافات لتسهيل الوصول للـ tenant و userId
    public String getTenantId() {
        return currentUser.getTenantId();
    }

    public Long getUserId() {
        return currentUser.getId();
    }

    public User getUser() {
        return currentUser;
    }
}