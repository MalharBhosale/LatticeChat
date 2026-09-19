package com.securechat.common.dto;

/**
 * Request DTO for updating message delivery or read receipts.
 */
public record DeliveryReceiptRequest(
        String status
) {
    public DeliveryReceiptRequest {
        if (status == null || status.isBlank()) {
            status = "READ";
        }
    }
}
