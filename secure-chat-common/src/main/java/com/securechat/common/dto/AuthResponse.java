package com.securechat.common.dto;

public record AuthResponse(
        String token,
        String tokenType,
        long expiresInSeconds,
        UserDto user
) {
    public static AuthResponse bearer(String token, long expiresInSeconds, UserDto user) {
        return new AuthResponse(token, "Bearer", expiresInSeconds, user);
    }
}
