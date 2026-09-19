package com.securechat.common.dto;

import java.time.Instant;

public record UserDto(
        Long id,
        String username,
        String email,
        boolean online,
        Instant lastSeenAt
) {}
