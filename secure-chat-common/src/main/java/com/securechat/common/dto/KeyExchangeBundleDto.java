package com.securechat.common.dto;

/**
 * Key exchange bundle fetched by a sender to initiate an asynchronous
 * PQ-X3DH session with a recipient. Contains the recipient's identity key,
 * signed prekey, prekey signature, and an optional claimed one-time prekey.
 */
public record KeyExchangeBundleDto(
        Long userId,
        String username,
        String identityKey,
        String identityAlgorithm,
        String signedPrekey,
        String signedPrekeyAlgorithm,
        String signedPrekeySignature,
        Integer oneTimePrekeyId,
        String oneTimePrekey,
        String oneTimePrekeyAlgorithm,
        int keyVersion
) {}
