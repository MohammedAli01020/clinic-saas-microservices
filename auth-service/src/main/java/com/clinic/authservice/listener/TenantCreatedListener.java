package com.clinic.authservice.listener;


import com.clinic.authservice.service.AuthService;
import com.clinic.sharedlib.kafka.EventModels;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class TenantCreatedListener {

    private final AuthService authService;

    @KafkaListener(topics = "tenant-created", groupId = "auth-service-group", concurrency = "2")
    public void onTenantCreated(EventModels.TenantCreatedEvent event) {
        log.info("Received tenant-created: {}", event.getTenantId());
        try {
            authService.createAdminFromTenant(event.getTenantId(), event.getOwnerEmail(), event.getCorrelationId());
        } catch (Exception ex) {
            log.error("Failed onboarding: {}", ex.getMessage(), ex);
            throw ex; // allow retry / DLQ
        }
    }
}
