package com.clinic.authservice.domain;

import com.clinic.authservice.domain.enums.AuthProvider;
import com.clinic.authservice.domain.enums.AuthUserStatus;
import com.clinic.sharedlib.audit.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table(
        name = "auth_users",
        indexes = {
                @Index(name = "idx_auth_user_email", columnList = "email", unique = true),
                @Index(name = "idx_auth_user_tenant_email", columnList = "tenant_id,email", unique = true)
        }
)
public class AuthUser extends BaseEntity {

    @Column(nullable = false, unique = true)
    private String email;

    @JsonIgnore
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private AuthProvider provider = AuthProvider.LOCAL;

    private String providerId; // Google sub, nullable

    @Builder.Default
    private boolean enabled = false;

    @Builder.Default
    private boolean emailVerified = false;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private AuthUserStatus status = AuthUserStatus.ACTIVE;

    // tenantId inherited from BaseEntity
    // createdAt, updatedAt, createdBy, updatedBy inherited from BaseEntity


//    @PrePersist
//    protected void onCreate() {
//        if (status == null) status = AuthUserStatus.ACTIVE;
//        if (provider == null) provider = AuthProvider.LOCAL;
//    }
}


