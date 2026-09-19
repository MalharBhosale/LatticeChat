package com.securechat.common.dto;

import java.util.List;

/**
 * Request payload for rotating a user's signed prekey and replenishing one-time prekeys.
 * The new prekey must be authentic and signed by the user's permanent ML-DSA-65 identity key.
 */
public record RotateKeyBundleRequest(
        String newPrekey,
        String newPrekeyAlgorithm,
        String newPrekeySignature,
        List<OneTimePrekeyUploadDto> oneTimePrekeys
) {}
