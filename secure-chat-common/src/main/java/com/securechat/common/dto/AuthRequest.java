package com.securechat.common.dto;

public record AuthRequest(
        String username,
        String password
) {}
