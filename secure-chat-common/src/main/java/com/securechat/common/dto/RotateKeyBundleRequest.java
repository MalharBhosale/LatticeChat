package com.securechat.common.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.List;

/**
 * Request payload for rotating a user's signed prekey and replenishing one-time prekeys.
 * The new prekey must be authentic and signed by the user's permanent ML-DSA-65 identity key.
 */
public record RotateKeyBundleRequest(
        @NotBlank(message = "New prekey cannot be blank")
        String newPrekey,

        String newPrekeyAlgorithm,

        @NotBlank(message = "New prekey signature cannot be blank")
        String newPrekeySignature,

        List<OneTimePrekeyUploadDto> oneTimePrekeys
) {}
