package com.clinic.sharedlib.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Builder;

import java.time.Instant;
import java.util.Set;

/**
 * Immutable DTO representing identity decoded from JWT.
 * Use this to forward identity to services (or place in request context).
 */
@Builder
public record JwtUserInfo(String userId, String email, String tenantId,
                   Set<String> roles, boolean emailVerified, boolean enabled,
                   Instant issuedAt, Instant expiresAt) {

}
