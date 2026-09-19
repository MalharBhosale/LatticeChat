package com.securechat.common.dto;

/**
 * DTO for requesting explicit revocation / invalidation of an active Post-Quantum Key Bundle.
 * Used for emergency key retirement, suspected device compromise, or user-initiated key reset.
 */
public record RevokeKeyBundleRequest(
        String reason,
        String notes
) {
    public RevokeKeyBundleRequest(String reason) {
        this(reason, null);
    }
}
