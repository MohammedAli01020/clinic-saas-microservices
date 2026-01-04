package com.clinic.authservice.repository;


import com.clinic.authservice.domain.AuthUser;
import com.clinic.authservice.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.List;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {


    List<RefreshToken> findByUserAndRevokedFalse(AuthUser user);

    Optional<RefreshToken> findByTokenHashAndTenantId(String tokenHash, String tenantId);

}
