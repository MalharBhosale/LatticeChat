package com.securechat.common.dto;

import java.time.Instant;

/**
 * DTO broadcast over WebSocket (/topic/presence) representing user online status changes.
 */
public record UserPresenceDto(
        String username,
        boolean online,
        Instant timestamp
) {}
