package com.clinic.authservice.domain;

import com.clinic.sharedlib.audit.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "refresh_tokens")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class RefreshToken {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="token_hash", length=512)
    private String tokenHash;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private AuthUser user;

    private String device;
    private String ip;
    private Instant createdAt = Instant.now();
    private Instant expiresAt;
    private boolean revoked = false;
}
