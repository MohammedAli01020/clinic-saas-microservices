package com.clinic.sharedlib.audit;

import com.clinic.sharedlib.tenant.TenantContext;
import com.clinic.sharedlib.tenant.UserContext;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;

import java.time.Instant;

public class AuditEntityListener {

    @PrePersist
    public void prePersist(BaseEntity entity) {
        String tenantId = TenantContext.getTenantId();
        String userId = UserContext.getCurrentUserId();
//        String userId = UserContext.getUser().userId();


        entity.setTenantId(tenantId);
        entity.setCreatedAt(Instant.now());
        entity.setCreatedBy(userId);
    }

    @PreUpdate
    public void preUpdate(BaseEntity entity) {
        String userId = UserContext.getCurrentUserId();

        entity.setUpdatedAt(Instant.now());
        entity.setUpdatedBy(userId);
    }
}
