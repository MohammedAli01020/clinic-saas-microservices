package com.clinic.authservice.security;

import com.clinic.authservice.repository.UserRepository;
import com.clinic.sharedlib.jwt.JwtUserInfo;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        var user = userRepository.findByEmail(email)
                .orElseThrow( () -> new UsernameNotFoundException("User not found: " + email));


        return new CustomerUserDetailsImpl(user);
    }
}
