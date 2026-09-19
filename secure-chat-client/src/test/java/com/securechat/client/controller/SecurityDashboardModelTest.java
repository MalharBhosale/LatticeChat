package com.securechat.client.controller;

import com.securechat.client.crypto.ClientKeystore;
import com.securechat.client.storage.LocalStorageService;
import com.securechat.common.crypto.KeyExchangeService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class SecurityDashboardModelTest {

    private LocalStorageService storage;

    @BeforeEach
    void setUp() throws Exception {
        storage = LocalStorageService.inMemory();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (storage != null) {
            storage.close();
        }
    }

    @Test
    @DisplayName("Should track peer verification status in local storage")
    void testPeerVerificationLifecycle() throws Exception {
        storage.saveSession("charlie", "sessionKeyB64", "peerIdentityKeyB64");

        // Newly created peer sessions must start as UNVERIFIED
        assertFalse(storage.isPeerVerified("charlie"), "Peer session should default to unverified");

        // Mark as verified
        storage.setPeerVerified("charlie", true);
        assertTrue(storage.isPeerVerified("charlie"), "Peer session should report verified after toggle");

        // Toggle back to unverified
        storage.setPeerVerified("charlie", false);
        assertFalse(storage.isPeerVerified("charlie"), "Peer session should report unverified after revoking verification");
    }

    @Test
    @DisplayName("Should persist peer verification across database connections")
    void testPeerVerificationPersistenceAcrossInstances(@TempDir Path tempDir) throws Exception {
        Path dbPath = tempDir.resolve("test_storage.db");

        // Session 1: Create session and verify
        try (LocalStorageService storage1 = new LocalStorageService(dbPath.toAbsolutePath().toString())) {
            storage1.saveSession("dave", "sessionKey123", "peerIdKey456");
            assertFalse(storage1.isPeerVerified("dave"));
            storage1.setPeerVerified("dave", true);
            assertTrue(storage1.isPeerVerified("dave"));
        }

        // Session 2: Reopen same database file
        try (LocalStorageService storage2 = new LocalStorageService(dbPath.toAbsolutePath().toString())) {
            assertTrue(storage2.isPeerVerified("dave"), "Verification flag must survive database restart");
            assertEquals("sessionKey123", storage2.getSessionKey("dave").orElseThrow());
            assertEquals("peerIdKey456", storage2.getPeerIdentityKey("dave").orElseThrow());
        }
    }

    @Test
    @DisplayName("Should compute commutative and deterministic 12-digit safety numbers")
    void testDeterministicSafetyNumber() {
        String keyAlice = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4, 5});
        String keyBob = Base64.getEncoder().encodeToString(new byte[]{6, 7, 8, 9, 10});
        String keyEve = Base64.getEncoder().encodeToString(new byte[]{11, 12, 13, 14, 15});

        String safetyAliceBob = SecurityDashboardController.computeSafetyNumber(keyAlice, keyBob);
        String safetyBobAlice = SecurityDashboardController.computeSafetyNumber(keyBob, keyAlice);
        String safetyAliceEve = SecurityDashboardController.computeSafetyNumber(keyAlice, keyEve);

        assertNotNull(safetyAliceBob);
        assertTrue(safetyAliceBob.matches("^\\d{6} \\d{6}$"), "Safety number must be format '000000 000000'");

        // Commutative property: (Alice, Bob) == (Bob, Alice)
        assertEquals(safetyAliceBob, safetyBobAlice, "Safety number must be commutative for out-of-band mutual verification");

        // Distinct identities must produce distinct safety numbers
        assertNotEquals(safetyAliceBob, safetyAliceEve, "Different keys must yield distinct safety numbers");
    }

    @Test
    @DisplayName("Should calculate prekey pool metrics and track one-time prekey consumption")
    void testOpkPoolTelemetryMetrics() {
        ClientKeystore keystore = ClientKeystore.generateNew(5);
        assertEquals(5, keystore.getOneTimePrekeys().size(), "Should initialize with 5 OPKs");

        // Consume an OPK (as would happen during session initiation)
        var consumed = keystore.consumeOneTimePrekey(1L);
        assertNotNull(consumed, "Consumed OPK must not be null");
        assertEquals(4, keystore.getOneTimePrekeys().size(), "Available OPKs should decrement to 4");

        // Replenish OPK pool
        KeyExchangeService kemService = new MlKemKeyExchangeService();
        keystore.addOneTimePrekey(99L, kemService.generateKeyPair());
        assertEquals(5, keystore.getOneTimePrekeys().size(), "Replenished pool should return to 5 available OPKs");
    }
}
