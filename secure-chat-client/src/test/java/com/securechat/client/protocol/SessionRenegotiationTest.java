package com.securechat.client.protocol;

import com.securechat.client.crypto.ClientKeystore;
import com.securechat.client.storage.LocalStorageService;
import com.securechat.client.storage.LocalMessage;
import com.securechat.common.dto.EncryptedMessageDto;
import com.securechat.common.dto.KeyExchangeBundleDto;
import com.securechat.common.dto.SendMessageRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SessionRenegotiationTest {

    private ClientKeystore aliceKeystore;
    private ClientKeystore bobKeystoreV1;
    private ClientKeystore bobKeystoreV2;

    private LocalStorageService aliceStorage;
    private LocalStorageService bobStorage;

    private PqSessionManager aliceSessionMgr;
    private PqSessionManager bobSessionMgr;

    @BeforeAll
    static void initCrypto() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        aliceKeystore = ClientKeystore.generateNew(5);
        bobKeystoreV1 = ClientKeystore.generateNew(5);
        bobKeystoreV2 = ClientKeystore.generateNew(5);

        aliceStorage = LocalStorageService.inMemory();
        bobStorage = LocalStorageService.inMemory();

        aliceSessionMgr = new PqSessionManager("alice", aliceKeystore, aliceStorage);
        bobSessionMgr = new PqSessionManager("bob", bobKeystoreV1, bobStorage);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (aliceStorage != null) aliceStorage.close();
        if (bobStorage != null) bobStorage.close();
    }

    @Test
    @DisplayName("Should re-negotiate session upon peer key bundle rotation to version 2")
    void testSessionRenegotiationWithRotatedBundle() throws Exception {
        // 1. Setup Bob's V1 bundle
        String bobIdKeyB64 = Base64.getEncoder().encodeToString(bobKeystoreV1.getIdentityKey().publicKey());
        String bobSpkB64 = Base64.getEncoder().encodeToString(bobKeystoreV1.getSignedPrekey().publicKey());
        String bobSpkSigB64 = Base64.getEncoder().encodeToString(bobKeystoreV1.getSignedPrekeySignature());
        String bobOpk1B64 = Base64.getEncoder().encodeToString(bobKeystoreV1.getOneTimePrekey(1L).publicKey());

        KeyExchangeBundleDto bobBundleV1 = new KeyExchangeBundleDto(
                2L, "bob",
                bobIdKeyB64, "ML-DSA-65",
                bobSpkB64, "ML-KEM-768",
                bobSpkSigB64,
                1, bobOpk1B64, "ML-KEM-768",
                1 // keyVersion = 1
        );

        // Alice establishes V1 session
        String ephemeralKemV1 = aliceSessionMgr.initiateSession("bob", bobBundleV1);
        assertTrue(aliceSessionMgr.hasActiveSession("bob"));
        assertEquals(1, aliceSessionMgr.getPeerKeyVersion("bob"));
        Optional<String> v1AliceSessionKeyOpt = aliceStorage.getSessionKey("bob");
        assertTrue(v1AliceSessionKeyOpt.isPresent());
        String v1AliceSessionKey = v1AliceSessionKeyOpt.get();

        // Alice sends message 1 to Bob
        SendMessageRequest req1 = aliceSessionMgr.prepareOutgoingMessage(
                "bob", "First message under V1 session key", ephemeralKemV1, 1L
        );
        String aliceIdKeyB64 = Base64.getEncoder().encodeToString(aliceKeystore.getIdentityKey().publicKey());
        EncryptedMessageDto dto1 = new EncryptedMessageDto(
                101L, req1.messageId(), 1L, "alice", 2L, "bob",
                req1.ciphertext(), req1.nonce(), req1.ephemeralKemCiphertext(),
                req1.signature(), req1.sequenceNumber(), "SENT", Instant.now(), null, null
        );
        LocalMessage decrypted1 = bobSessionMgr.processIncomingMessage(dto1, aliceIdKeyB64);
        assertEquals("First message under V1 session key", decrypted1.plaintext());

        // 2. Bob rotates his key bundle to V2
        bobSessionMgr = new PqSessionManager("bob", bobKeystoreV2, bobStorage);

        String bobIdKey2B64 = Base64.getEncoder().encodeToString(bobKeystoreV2.getIdentityKey().publicKey());
        String bobSpk2B64 = Base64.getEncoder().encodeToString(bobKeystoreV2.getSignedPrekey().publicKey());
        String bobSpk2SigB64 = Base64.getEncoder().encodeToString(bobKeystoreV2.getSignedPrekeySignature());
        String bobOpk2B64 = Base64.getEncoder().encodeToString(bobKeystoreV2.getOneTimePrekey(1L).publicKey());

        KeyExchangeBundleDto bobBundleV2 = new KeyExchangeBundleDto(
                2L, "bob",
                bobIdKey2B64, "ML-DSA-65",
                bobSpk2B64, "ML-KEM-768",
                bobSpk2SigB64,
                1, bobOpk2B64, "ML-KEM-768",
                2 // keyVersion = 2
        );

        // 3. Alice re-negotiates session with Bob's V2 bundle
        String ephemeralKemV2 = aliceSessionMgr.renegotiateSession("bob", bobBundleV2);
        assertNotNull(ephemeralKemV2);
        assertEquals(2, aliceSessionMgr.getPeerKeyVersion("bob"));

        Optional<String> v2AliceSessionKeyOpt = aliceStorage.getSessionKey("bob");
        assertTrue(v2AliceSessionKeyOpt.isPresent());
        String v2AliceSessionKey = v2AliceSessionKeyOpt.get();
        assertNotEquals(v1AliceSessionKey, v2AliceSessionKey, "V2 session key must differ from V1 session key");

        // Alice sends message under new session
        SendMessageRequest req2 = aliceSessionMgr.prepareOutgoingMessage(
                "bob", "Second message under rotated V2 session key", ephemeralKemV2, 1L
        );
        EncryptedMessageDto dto2 = new EncryptedMessageDto(
                102L, req2.messageId(), 1L, "alice", 2L, "bob",
                req2.ciphertext(), req2.nonce(), req2.ephemeralKemCiphertext(),
                req2.signature(), req2.sequenceNumber(), "SENT", Instant.now(), null, null
        );
        LocalMessage decrypted2 = bobSessionMgr.processIncomingMessage(dto2, aliceIdKeyB64);
        assertEquals("Second message under rotated V2 session key", decrypted2.plaintext());
    }

    @Test
    @DisplayName("Should properly invalidate single session and clear all sessions")
    void testSessionInvalidation() throws Exception {
        String bobIdKeyB64 = Base64.getEncoder().encodeToString(bobKeystoreV1.getIdentityKey().publicKey());
        String bobSpkB64 = Base64.getEncoder().encodeToString(bobKeystoreV1.getSignedPrekey().publicKey());
        String bobSpkSigB64 = Base64.getEncoder().encodeToString(bobKeystoreV1.getSignedPrekeySignature());
        String bobOpk1B64 = Base64.getEncoder().encodeToString(bobKeystoreV1.getOneTimePrekey(1L).publicKey());

        KeyExchangeBundleDto bobBundle = new KeyExchangeBundleDto(
                2L, "bob",
                bobIdKeyB64, "ML-DSA-65",
                bobSpkB64, "ML-KEM-768",
                bobSpkSigB64,
                1, bobOpk1B64, "ML-KEM-768",
                1
        );

        aliceSessionMgr.initiateSession("bob", bobBundle);
        assertTrue(aliceSessionMgr.hasActiveSession("bob"));
        assertTrue(aliceStorage.getSessionKey("bob").isPresent());

        // Invalidate session
        aliceSessionMgr.invalidateSession("bob");
        assertFalse(aliceSessionMgr.hasActiveSession("bob"));
        assertFalse(aliceStorage.getSessionKey("bob").isPresent());

        // Initiate again, then clear all
        aliceSessionMgr.initiateSession("bob", bobBundle);
        assertTrue(aliceSessionMgr.hasActiveSession("bob"));

        aliceSessionMgr.clearAllSessions();
        assertFalse(aliceSessionMgr.hasActiveSession("bob"));
        assertFalse(aliceStorage.getSessionKey("bob").isPresent());
    }
}
