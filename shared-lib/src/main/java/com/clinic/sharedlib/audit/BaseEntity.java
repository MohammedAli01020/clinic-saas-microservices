package com.clinic.sharedlib.audit;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.FilterDef;
import org.hibernate.annotations.ParamDef;

import java.time.Instant;

@MappedSuperclass
@EntityListeners(AuditEntityListener.class)

@FilterDef(
        name = "tenantFilter",
        parameters = @ParamDef(name = "tenantId", type = String.class)
)
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Getter
@Setter
public abstract class BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    protected Long id;

    @Column(name = "tenant_id", nullable = false)
    protected String tenantId;

    @Column(name = "created_at", nullable = false, updatable = false)
    protected Instant createdAt;

    @Column(name = "created_by")
    protected String createdBy;

    @Column(name = "updated_at")
    protected Instant updatedAt;

    @Column(name = "updated_by")
    protected String updatedBy;

}
