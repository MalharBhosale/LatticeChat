package com.securechat.common.dto;

import java.util.List;

/**
 * Request DTO for publishing or rotating a user's Post-Quantum Cryptographic Key Bundle.
 */
public record PublishKeyBundleRequest(
        String identityKey,
        String identityAlgorithm,
        String prekey,
        String prekeyAlgorithm,
        String prekeySignature,
        List<OneTimePrekeyUploadDto> oneTimePrekeys
) {
    public PublishKeyBundleRequest {
        if (identityAlgorithm == null || identityAlgorithm.isBlank()) {
            identityAlgorithm = "ML-DSA-65";
        }
        if (prekeyAlgorithm == null || prekeyAlgorithm.isBlank()) {
            prekeyAlgorithm = "ML-KEM-768";
        }
    }
}
