package com.securechat.common.dto;

/**
 * Request DTO for transmitting an End-to-End Encrypted message to a recipient.
 * The message payload (messageId + sequenceNumber + nonce + ciphertext) is digitally
 * signed by the sender's ML-DSA-65 identity key.
 */
public record SendMessageRequest(
        String recipientUsername,
        String messageId,
        String ciphertext,
        String nonce,
        String ephemeralKemCiphertext,
        String signature,
        long sequenceNumber
) {}
