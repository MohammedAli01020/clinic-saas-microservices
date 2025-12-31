package com.clinic.sharedlib.audit;

import com.clinic.sharedsecurityjwt.PrincipalType;
import com.clinic.sharedsecurityjwt.SecurityPrincipal;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;

@Slf4j
public class AuditEntityListener {

    @PrePersist
    public void prePersist(BaseEntity entity) {
        setAuditFields(entity, true);
    }

    @PreUpdate
    public void preUpdate(BaseEntity entity) {
        setAuditFields(entity, false);
    }

    private void setAuditFields(BaseEntity entity, boolean isNew) {
        String actor = resolveActor();
        Instant now = Instant.now();

        if (isNew) {
            entity.setCreatedBy(actor);
            entity.setCreatedAt(now);
        }

        entity.setUpdatedBy(actor);
        entity.setUpdatedAt(now);
    }


    private String resolveActor() {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !(auth.getPrincipal() instanceof SecurityPrincipal principal)) {
            log.debug("No authenticated principal found, using system");
            return "system";
        }

        if (principal.principalType() == PrincipalType.USER) {
            return principal.sub();
        }

        if (principal.principalType() == PrincipalType.SERVICE) {
            return "service:" + principal.sub();
        }

        return "system";
    }
}
