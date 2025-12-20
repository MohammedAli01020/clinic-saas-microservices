package com.clinic.authservice.domain;

import com.clinic.authservice.domain.enums.AuthProvider;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Builder
@Entity
@Getter
@Setter
@Table(name = "auth_users")
public class AuthUser {

    @Id
    @GeneratedValue
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    private String passwordHash;

    @Enumerated(EnumType.STRING)
    private AuthProvider provider;

    private String providerId; // Google sub

    private boolean enabled;
    private boolean emailVerified;

    private String tenantId; // nullable

    private Instant createdAt;
}




