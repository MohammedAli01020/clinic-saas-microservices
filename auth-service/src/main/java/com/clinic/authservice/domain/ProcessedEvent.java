package com.clinic.authservice.domain;

import com.clinic.sharedlib.audit.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "processed_events", uniqueConstraints = {@UniqueConstraint(columnNames = {"event_id"})})
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ProcessedEvent extends BaseEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name="event_id", nullable=false)
    private String eventId;
    private String topic;
    private Instant processedAt = Instant.now();
}
