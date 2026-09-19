package com.securechat.common.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTO for requesting explicit revocation / invalidation of an active Post-Quantum Key Bundle.
 * Used for emergency key retirement, suspected device compromise, or user-initiated key reset.
 */
public record RevokeKeyBundleRequest(
        @NotBlank(message = "Revocation reason cannot be blank")
        @Size(max = 255, message = "Reason cannot exceed 255 characters")
        String reason,

        @Size(max = 1000, message = "Notes cannot exceed 1000 characters")
        String notes
) {
    public RevokeKeyBundleRequest(String reason) {
        this(reason, null);
    }
}
