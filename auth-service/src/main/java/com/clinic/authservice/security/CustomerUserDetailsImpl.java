package com.clinic.authservice.security;


import com.clinic.authservice.domain.User;
import com.clinic.sharedlib.jwt.JwtUserInfo;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class CustomerUserDetailsImpl implements UserDetails {

    private final User userInfo;

    public CustomerUserDetailsImpl(User userInfo) {
        this.userInfo = userInfo;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (userInfo.getRoles() == null) {
            return List.of();
        }
        return userInfo.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.toString()))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        // عادة الـ password لا يُخزن في UserInfo إذا جاي من JWT
        return userInfo.getPasswordHash();
    }

    @Override
    public String getUsername() {
        return userInfo.getEmail();
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
        return userInfo.isEnabled();
    }

    // إضافات لتسهيل الوصول للـ tenant و userId
    public String getTenantId() {
        return userInfo.getTenantId();
    }

    public Long getUserId() {
        return userInfo.getId();
    }

    public User getUser() {
        return userInfo;
    }
}