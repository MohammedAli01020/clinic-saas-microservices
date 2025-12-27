package com.clinic.usermanagementservice.domain;

import com.clinic.sharedlib.audit.BaseEntity;
import com.clinic.usermanagementservice.domain.enmus.UserStatus;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_tenant_email", columnList = "tenant_id,email", unique = true),
        @Index(name = "idx_user_authTenant", columnList = "authUserId,tenant_id")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class User extends BaseEntity {

    @Column(nullable = false)
    private Long authUserId;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String fullName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status = UserStatus.ACTIVE;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id")
    private Role role;

    public void softDelete() {
        this.status = UserStatus.DELETED;
        this.setDeleted(true);
    }
}
