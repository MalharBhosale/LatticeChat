package com.securechat.common.dto;

import java.time.Instant;

/**
 * DTO representing an End-to-End Encrypted message transmitted between peers via the server.
 * Contains only ciphertext, cryptographic nonces, signatures, and delivery metadata.
 */
public record EncryptedMessageDto(
        Long id,
        String messageId,
        Long senderId,
        String senderUsername,
        Long recipientId,
        String recipientUsername,
        String ciphertextBase64,
        String nonceBase64,
        String encapsulationCiphertextBase64,
        String signatureBase64,
        long sequenceNumber,
        String status,
        Instant sentAt,
        Instant deliveredAt,
        Instant readAt
) {}
