package com.clinic.usermanagementservice.repository;

import com.clinic.usermanagementservice.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

    Optional<User> findByAuthUserIdAndTenantId(Long authUserId, String tenantId);

    Optional<User> findByEmailAndTenantId(String email, String tenantId);
}
