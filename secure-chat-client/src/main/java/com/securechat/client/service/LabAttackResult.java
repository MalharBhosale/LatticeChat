package com.securechat.client.service;

import java.util.List;

/**
 * Forensic evaluation report emitted by an adversarial attack simulation in the Educational Security Lab.
 */
public record LabAttackResult(
        AttackType attackType,
        boolean defenseSuccessful,
        String title,
        String explanation,
        String defenseTriggered,
        List<String> forensicLogSteps,
        String technicalDetails,
        long elapsedMillis
) {
    public enum AttackType {
        REPLAY_ATTACK("Replay Attack & Packet Duplication"),
        CIPHERTEXT_TAMPERING("Ciphertext Bit-Flipping & AEAD Tampering"),
        BAD_SIGNATURE("Forged ML-DSA-65 Signature Injection"),
        IDOR_EXFILTRATION("IDOR / Unauthorized Attachment Exfiltration");

        private final String displayName;

        AttackType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }
}
