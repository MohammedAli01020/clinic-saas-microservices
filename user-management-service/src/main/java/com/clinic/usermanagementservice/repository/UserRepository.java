package com.clinic.usermanagementservice.repository;

import com.clinic.usermanagementservice.domain.User;
import com.clinic.usermanagementservice.dto.RolePermissionRow;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

    Optional<User> findByAuthUserId(Long authUserId);

    Optional<User> findByEmail(String email);

    Optional<User> findByAuthUserIdAndTenantId(Long authUserId, String tenantId);


    boolean existsByTenantIdAndEmail(String tenantId, String email);


    @Query("""
            SELECT new com.clinic.usermanagementservice.dto.RolePermissionRow(r.name, p.name)
            FROM User u
            LEFT JOIN u.role r
            LEFT JOIN r.permissions p
            WHERE u.authUserId = :id
            """)
    List<RolePermissionRow> findRolePermissionRows(@Param("id") Long id);


}
