package com.clinic.sharedlib.audit;

import com.clinic.sharedlib.jwt.CurrentUser;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;

@Slf4j
public class AuditEntityListener {

//    private static final Logger logger = LoggerFactory.getLogger(AuditEntityListener.class);

    @PrePersist
    public void prePersist(BaseEntity entity) {
        setAuditFields(entity, true);
    }

    @PreUpdate
    public void preUpdate(BaseEntity entity) {
        setAuditFields(entity, false);
    }

    private void setAuditFields(BaseEntity entity, boolean isNew) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String userId = "system";
//        String tenantId = "system";

        if (auth != null && auth.getPrincipal() instanceof CurrentUser user) {
            userId = user.userId();
//            tenantId = user.tenantId();
        } else {
            log.warn("No authenticated user found, defaulting to 'system'");
        }

        if (isNew) {
            entity.setCreatedBy(userId);
//            entity.setTenantId(tenantId);
            entity.setCreatedAt(Instant.now());
        }

        entity.setUpdatedBy(userId);
        entity.setUpdatedAt(Instant.now());
    }
}
