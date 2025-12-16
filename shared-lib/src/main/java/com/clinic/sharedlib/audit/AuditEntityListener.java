package com.clinic.sharedlib.audit;

import com.clinic.sharedlib.jwt.UserInfo;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;

public class AuditEntityListener {

    @PrePersist
    public void prePersist(BaseEntity entity) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserInfo user) {
            entity.setCreatedBy(user.userId());
            entity.setTenantId(user.tenantId());
        } else {

            entity.setCreatedBy("anonymous");
            entity.setTenantId("anonymous");
        }

        entity.setCreatedAt(Instant.now());

    }

    @PreUpdate
    public void preUpdate(BaseEntity entity) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserInfo user) {
            entity.setUpdatedBy(user.userId());
        } else {
            entity.setUpdatedBy("anonymous");
        }

        entity.setUpdatedAt(Instant.now());

    }
}
