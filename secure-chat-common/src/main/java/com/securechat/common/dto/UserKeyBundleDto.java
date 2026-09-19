package com.securechat.common.dto;

import java.time.Instant;

public record UserKeyBundleDto(
        Long userId,
        String username,
        String kemPublicKeyBase64,
        String kemAlgorithm,
        String dsaPublicKeyBase64,
        String dsaAlgorithm,
        int keyVersion,
        Instant publishedAt
) {}
