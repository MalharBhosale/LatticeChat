package com.securechat.common.dto;

import java.time.Instant;

/**
 * DTO representing an immutable security audit event returned to the client
 * for cryptographic lifecycle transparency and security forensics.
 */
public record AuditLogDto(
        Long id,
        String username,
        String eventType,
        String ipAddress,
        String details,
        Instant createdAt
) {}
