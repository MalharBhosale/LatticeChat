package com.securechat.common.dto;

import java.time.Instant;

public record EncryptedMessageDto(
        Long id,
        Long conversationId,
        Long senderId,
        String senderUsername,
        Long recipientId,
        String ciphertextBase64,
        String nonceBase64,
        String encapsulationCiphertextBase64,
        String signatureBase64,
        int keyVersion,
        long sequenceNumber,
        Instant timestamp
) {}
