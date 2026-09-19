package com.securechat.common.dto;

import java.time.Instant;

/**
 * DTO pushed to the original sender over WebSocket (/user/queue/receipts) upon delivery or read receipts.
 */
public record ReceiptNotificationDto(
        String messageId,
        String status,
        Instant timestamp
) {}
