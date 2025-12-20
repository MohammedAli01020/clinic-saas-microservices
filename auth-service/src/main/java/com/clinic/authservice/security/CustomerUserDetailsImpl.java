package com.clinic.authservice.security;


import com.clinic.authservice.domain.AuthUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.List;


public class CustomerUserDetailsImpl implements UserDetails {

    private final AuthUser authUser;

    public CustomerUserDetailsImpl(AuthUser authUser) {
        this.authUser = authUser;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // لا حاجة للـ roles هنا
        return List.of();
    }

    @Override
    public String getPassword() {
        return authUser.getPasswordHash();
    }

    @Override
    public String getUsername() {
        return authUser.getEmail();
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
        return authUser.isEnabled();
    }

    // ========= Helpers =========

    public String getTenantId() {
        return authUser.getTenantId();
    }

    public Long getUserId() {
        return authUser.getId();
    }
}
