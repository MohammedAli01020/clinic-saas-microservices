package com.clinic.usermanagementservice.repository;

import com.clinic.usermanagementservice.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByNameAndTenantId(String name, String tenantId);

    Optional<Role> findByName(String name);



}
