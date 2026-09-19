package com.securechat.common.dto;

import java.time.Instant;

/**
 * DTO representing an end-to-end encrypted file attachment metadata transmitted between peers.
 * The server never knows the plaintext file content or filename.
 */
public record EncryptedAttachmentDto(
        Long id,
        String fileId,
        Long uploaderId,
        String uploaderUsername,
        Long recipientId,
        String recipientUsername,
        String encryptedFilename,
        String mimeType,
        long fileSizeBytes,
        String nonceBase64,
        Instant createdAt
) {}
