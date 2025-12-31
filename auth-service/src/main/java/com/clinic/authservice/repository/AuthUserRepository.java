package com.clinic.authservice.repository;


import com.clinic.authservice.domain.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface AuthUserRepository extends JpaRepository<AuthUser, Long> {
    Optional<AuthUser> findByEmail(String email);

    boolean existsByEmailAndTenantId(String email, String tenantId);
}
