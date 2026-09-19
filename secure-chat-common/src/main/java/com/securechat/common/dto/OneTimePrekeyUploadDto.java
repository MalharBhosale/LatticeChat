package com.securechat.common.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * DTO representing an individual one-time prekey upload (ML-KEM-768).
 */
public record OneTimePrekeyUploadDto(
        int keyId,

        @NotBlank(message = "Public key cannot be blank")
        String publicKey,

        String algorithm
) {
    public OneTimePrekeyUploadDto {
        if (algorithm == null || algorithm.isBlank()) {
            algorithm = "ML-KEM-768";
        }
    }
}
