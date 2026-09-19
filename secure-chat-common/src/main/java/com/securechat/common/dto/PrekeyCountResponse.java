package com.securechat.common.dto;

/**
 * Response DTO providing status of the user's available one-time prekeys.
 */
public record PrekeyCountResponse(
        long remainingCount,
        boolean lowStock
) {}
