package com.securechat.common.dto;

/**
 * DTO representing an individual one-time prekey upload (ML-KEM-768).
 */
public record OneTimePrekeyUploadDto(
        int keyId,
        String publicKey,
        String algorithm
) {
    public OneTimePrekeyUploadDto {
        if (algorithm == null || algorithm.isBlank()) {
            algorithm = "ML-KEM-768";
        }
    }
}
