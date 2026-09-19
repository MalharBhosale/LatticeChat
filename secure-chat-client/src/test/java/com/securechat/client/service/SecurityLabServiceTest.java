package com.securechat.client.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecurityLabServiceTest {

    private SecurityLabService labService;

    @BeforeEach
    void setUp() {
        labService = new SecurityLabService();
    }

    @Test
    @DisplayName("Lab Simulation 1: Replay Attack should be detected and blocked by defense shield")
    void testReplayAttackSimulation() {
        LabAttackResult result = labService.simulateReplayAttack("charlie");

        assertNotNull(result);
        assertEquals(LabAttackResult.AttackType.REPLAY_ATTACK, result.attackType());
        assertTrue(result.defenseSuccessful(), "Replay attack must trigger defensive block");
        assertTrue(result.defenseTriggered().contains("REPLAY"), "Must identify replay defense shield");
        assertFalse(result.forensicLogSteps().isEmpty(), "Forensic logs must be generated");
        assertTrue(result.forensicLogSteps().stream().anyMatch(s -> s.contains("[DEFENSE_TRIGGERED]")));
    }

    @Test
    @DisplayName("Lab Simulation 2: Ciphertext bit-flipping must fail AES-256-GCM AEAD authentication")
    void testCiphertextBitFlippingTamper() {
        String testPayload = "Top Secret Classified Document Content";
        LabAttackResult result = labService.simulateCiphertextTamper(testPayload, 3);

        assertNotNull(result);
        assertEquals(LabAttackResult.AttackType.CIPHERTEXT_TAMPERING, result.attackType());
        assertTrue(result.defenseSuccessful(), "Bit-flipping must be caught by AEAD integrity check");
        assertTrue(result.defenseTriggered().contains("AES-256-GCM"), "Must identify AES-GCM AEAD shield");
        assertTrue(result.forensicLogSteps().stream().anyMatch(s -> s.contains("[DEFENSE_TRIGGERED]")));
        assertTrue(result.forensicLogSteps().stream().anyMatch(s -> s.contains("Zero bytes of plaintext decrypted")));
    }

    @Test
    @DisplayName("Lab Simulation 3: Modified message payload must fail NIST FIPS 204 ML-DSA-65 verification")
    void testBadSignatureInjection() {
        String testPayload = "Transfer $1,000 to Bob";
        LabAttackResult result = labService.simulateBadSignature(testPayload);

        assertNotNull(result);
        assertEquals(LabAttackResult.AttackType.BAD_SIGNATURE, result.attackType());
        assertTrue(result.defenseSuccessful(), "Altered message must fail ML-DSA-65 verification");
        assertTrue(result.defenseTriggered().contains("ML-DSA-65"), "Must identify ML-DSA-65 shield");
        assertTrue(result.forensicLogSteps().stream().anyMatch(s -> s.contains("SIGNATURE_VERIFICATION_FAILED")));
    }

    @Test
    @DisplayName("Lab Simulation 4: IDOR unauthorized access must be blocked by ownership enforcement")
    void testIdorAccessSimulation() {
        String simulatedFileId = "doc-file-uuid-test";
        LabAttackResult result = labService.simulateIdorAccess(simulatedFileId);

        assertNotNull(result);
        assertEquals(LabAttackResult.AttackType.IDOR_EXFILTRATION, result.attackType());
        assertTrue(result.defenseSuccessful(), "Unauthorized exfiltration must be blocked");
        assertTrue(result.defenseTriggered().contains("SHIELD"));
        assertTrue(result.forensicLogSteps().stream().anyMatch(s -> s.contains("[DEFENSE_TRIGGERED]")));
    }
}
