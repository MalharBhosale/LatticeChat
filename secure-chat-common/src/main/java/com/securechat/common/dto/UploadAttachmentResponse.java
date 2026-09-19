package com.securechat.common.dto;

import java.time.Instant;

/**
 * Response DTO returned after successfully uploading an encrypted attachment blob to the server.
 */
public record UploadAttachmentResponse(
        String fileId,
        long fileSizeBytes,
        Instant createdAt
) {}
