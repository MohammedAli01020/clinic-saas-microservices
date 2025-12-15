package com.clinic.authservice.security;


import com.clinic.authservice.repository.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;

    private final JwtService jwtService;

    public JwtAuthenticationFilter(UserRepository userRepository,@Lazy JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, jakarta.servlet.ServletException {
        String header = req.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {

//                DecodedJWT decoded = jwtService.decode(token);
//                String userId = decoded.getSubject();
//                String tenant = decoded.getClaim("tenant").asString();
//                List<String> roles = decoded.getClaim("roles").asList(String.class)

                jwtService.verify(token);

//                DecodedJWT decoded = jwtService.decode(token);

//                decoded.getClaims()
//                UserInfo userInfo = jwtService.toUserInfo(decoded.getClaims());

//                var authorities =
//                        userInfo.roles().stream().map(r -> new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_" + r)).collect(Collectors.toList());
//
//                Optional<User> currentUser = userRepository.findById(Long.valueOf(userInfo.userId()));



//                if (currentUser.isPresent()) {
//                    CustomerUserDetailsImpl userDetails = new CustomerUserDetailsImpl(currentUser.get());
//                    UsernamePasswordAuthenticationToken auth =
//                            new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
//                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
//                SecurityContextHolder.getContext().setAuthentication(auth);
//                }

            } catch (Exception ex) {
                // invalid token -> clear context
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(req, res);
    }
}
