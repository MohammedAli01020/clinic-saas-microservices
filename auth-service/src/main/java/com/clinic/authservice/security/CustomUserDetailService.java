package com.clinic.authservice.security;

import com.clinic.authservice.repository.AuthUserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailService implements UserDetailsService {
    private final AuthUserRepository authUserRepository;

    public CustomUserDetailService(AuthUserRepository authUserRepository) {
        this.authUserRepository = authUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        var user = authUserRepository.findByEmail(email)
                .orElseThrow( () -> new UsernameNotFoundException("User not found: " + email));


        return new CustomerUserDetailsImpl(user);
    }
}
