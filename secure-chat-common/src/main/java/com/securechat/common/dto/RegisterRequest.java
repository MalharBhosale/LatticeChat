package com.securechat.common.dto;

public record RegisterRequest(
        String username,
        String password,
        String email,
        String kemPublicKeyBase64,
        String dsaPublicKeyBase64
) {}
