package com.securechat.common.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request DTO for transmitting an End-to-End Encrypted message to a recipient.
 * The message payload (messageId + sequenceNumber + nonce + ciphertext) is digitally
 * signed by the sender's ML-DSA-65 identity key.
 */
public record SendMessageRequest(
        @NotBlank(message = "Recipient username cannot be blank")
        @Size(min = 3, max = 50, message = "Recipient username must be between 3 and 50 characters")
        String recipientUsername,

        @NotBlank(message = "Message ID cannot be blank")
        @Size(max = 128, message = "Message ID cannot exceed 128 characters")
        String messageId,

        @NotBlank(message = "Ciphertext cannot be blank")
        String ciphertext,

        @NotBlank(message = "Nonce cannot be blank")
        String nonce,

        String ephemeralKemCiphertext,

        @NotBlank(message = "Digital signature cannot be blank")
        String signature,

        @Min(value = 0, message = "Sequence number must be non-negative")
        long sequenceNumber
) {}
