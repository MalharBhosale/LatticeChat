package com.securechat.common.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.List;

/**
 * Request DTO for publishing or rotating a user's Post-Quantum Cryptographic Key Bundle.
 */
public record PublishKeyBundleRequest(
        @NotBlank(message = "Identity key cannot be blank")
        String identityKey,

        String identityAlgorithm,

        @NotBlank(message = "Prekey cannot be blank")
        String prekey,

        String prekeyAlgorithm,

        @NotBlank(message = "Prekey signature cannot be blank")
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
