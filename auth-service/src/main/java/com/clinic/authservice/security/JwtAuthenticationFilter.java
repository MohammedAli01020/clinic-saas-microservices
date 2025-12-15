package com.clinic.authservice.security;


import com.auth0.jwt.interfaces.DecodedJWT;
import com.clinic.authservice.domain.User;
import com.clinic.authservice.repository.UserRepository;
import com.clinic.sharedlib.jwt.JwtUserInfo;
import com.clinic.sharedlib.jwt.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;

    private final JwtUtils jwtUtils;

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

                jwtUtils.validateJwtToken(token);
                JwtUserInfo userInfo = jwtUtils.parseTokenAuto(token);

                var authorities =
                        userInfo.roles().stream().map(r -> new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_" + r)).collect(Collectors.toList());

                Optional<User> currentUser = userRepository.findById(Long.valueOf(userInfo.userId()));



                if (currentUser.isPresent()) {
                    CustomerUserDetailsImpl userDetails = new CustomerUserDetailsImpl(currentUser.get());
                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                SecurityContextHolder.getContext().setAuthentication(auth);
                }

            } catch (Exception ex) {
                // invalid token -> clear context
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(req, res);
    }
}
