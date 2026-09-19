package com.securechat.common.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Request DTO for updating message delivery or read receipts.
 */
public record DeliveryReceiptRequest(
        @NotBlank(message = "Status cannot be blank")
        @Pattern(regexp = "(?i)SENT|DELIVERED|READ|FAILED", message = "Invalid delivery status: must be SENT, DELIVERED, READ, or FAILED")
        String status
) {
    public DeliveryReceiptRequest {
        if (status == null || status.isBlank()) {
            status = "READ";
        }
    }
}
