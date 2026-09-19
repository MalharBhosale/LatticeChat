package com.securechat.client.protocol;

import com.securechat.client.crypto.ClientKeystore;
import com.securechat.client.storage.LocalStorageService;
import com.securechat.client.storage.LocalMessage;
import com.securechat.common.dto.EncryptedMessageDto;
import com.securechat.common.dto.KeyExchangeBundleDto;
import com.securechat.common.dto.SendMessageRequest;
import com.securechat.common.exception.CryptoException;
import com.securechat.common.exception.MessageDecryptionException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PqSessionManagerTest {

    private ClientKeystore aliceKeystore;
    private ClientKeystore bobKeystore;

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
        bobKeystore = ClientKeystore.generateNew(5);

        aliceStorage = LocalStorageService.inMemory();
        bobStorage = LocalStorageService.inMemory();

        aliceSessionMgr = new PqSessionManager("alice", aliceKeystore, aliceStorage);
        bobSessionMgr = new PqSessionManager("bob", bobKeystore, bobStorage);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (aliceStorage != null) aliceStorage.close();
        if (bobStorage != null) bobStorage.close();
    }

    @Test
    @DisplayName("Should establish end-to-end PQ-X3DH session and exchange encrypted messages bidirectionally")
    void testEndToEndPqX3dhExchange() throws Exception {
        // 1. Bob's public key bundle (published on server)
        String bobIdKeyB64 = Base64.getEncoder().encodeToString(bobKeystore.getIdentityKey().publicKey());
        String bobSpkB64 = Base64.getEncoder().encodeToString(bobKeystore.getSignedPrekey().publicKey());
        String bobSpkSigB64 = Base64.getEncoder().encodeToString(bobKeystore.getSignedPrekeySignature());
        String bobOpk1B64 = Base64.getEncoder().encodeToString(bobKeystore.getOneTimePrekey(1L).publicKey());

        KeyExchangeBundleDto bobBundle = new KeyExchangeBundleDto(
                2L, "bob",
                bobIdKeyB64, "ML-DSA-65",
                bobSpkB64, "ML-KEM-768",
                bobSpkSigB64,
                1, bobOpk1B64, "ML-KEM-768",
                1
        );

        // 2. Alice initiates session with Bob
        assertFalse(aliceSessionMgr.hasActiveSession("bob"));
        String ephemeralKem = aliceSessionMgr.initiateSession("bob", bobBundle);
        assertTrue(aliceSessionMgr.hasActiveSession("bob"));
        assertNotNull(ephemeralKem);

        // 3. Alice prepares initial message to Bob
        SendMessageRequest aliceReq = aliceSessionMgr.prepareOutgoingMessage(
                "bob",
                "Hello Bob! Post-Quantum Lattice Cryptography is active.",
                ephemeralKem,
                1L
        );

        // 4. Simulate server relaying to Bob
        String aliceIdKeyB64 = Base64.getEncoder().encodeToString(aliceKeystore.getIdentityKey().publicKey());
        EncryptedMessageDto incomingToBob = new EncryptedMessageDto(
                101L,
                aliceReq.messageId(),
                1L, "alice",
                2L, "bob",
                aliceReq.ciphertext(),
                aliceReq.nonce(),
                aliceReq.ephemeralKemCiphertext(),
                aliceReq.signature(),
                aliceReq.sequenceNumber(),
                "SENT",
                Instant.now(), null, null
        );

        assertFalse(bobSessionMgr.hasActiveSession("alice"));

        // 5. Bob processes incoming message
        LocalMessage bobDecrypted = bobSessionMgr.processIncomingMessage(incomingToBob, aliceIdKeyB64);

        assertTrue(bobSessionMgr.hasActiveSession("alice"));
        assertEquals("Hello Bob! Post-Quantum Lattice Cryptography is active.", bobDecrypted.plaintext());
        assertEquals("alice", bobDecrypted.peerUsername());
        assertEquals("INCOMING", bobDecrypted.direction());

        // 6. Bob prepares reply to Alice (session is already established, no ephemeralKem needed)
        SendMessageRequest bobReplyReq = bobSessionMgr.prepareOutgoingMessage(
                "alice",
                "Hi Alice! Received and decrypted with ML-KEM-768 and AES-256-GCM.",
                null,
                2L
        );

        EncryptedMessageDto incomingToAlice = new EncryptedMessageDto(
                102L,
                bobReplyReq.messageId(),
                2L, "bob",
                1L, "alice",
                bobReplyReq.ciphertext(),
                bobReplyReq.nonce(),
                bobReplyReq.ephemeralKemCiphertext(),
                bobReplyReq.signature(),
                bobReplyReq.sequenceNumber(),
                "SENT",
                Instant.now(), null, null
        );

        // 7. Alice processes Bob's reply
        LocalMessage aliceDecrypted = aliceSessionMgr.processIncomingMessage(incomingToAlice, bobIdKeyB64);
        assertEquals("Hi Alice! Received and decrypted with ML-KEM-768 and AES-256-GCM.", aliceDecrypted.plaintext());
        assertEquals("bob", aliceDecrypted.peerUsername());
        assertEquals("INCOMING", aliceDecrypted.direction());
    }

    @Test
    @DisplayName("Should reject tampered ciphertext with MessageDecryptionException")
    void testTamperedCiphertextRejected() throws Exception {
        String bobIdKeyB64 = Base64.getEncoder().encodeToString(bobKeystore.getIdentityKey().publicKey());
        String bobSpkB64 = Base64.getEncoder().encodeToString(bobKeystore.getSignedPrekey().publicKey());
        String bobSpkSigB64 = Base64.getEncoder().encodeToString(bobKeystore.getSignedPrekeySignature());

        KeyExchangeBundleDto bobBundle = new KeyExchangeBundleDto(
                2L, "bob",
                bobIdKeyB64, "ML-DSA-65",
                bobSpkB64, "ML-KEM-768",
                bobSpkSigB64,
                null, null, null,
                1
        );

        String ephemeralKem = aliceSessionMgr.initiateSession("bob", bobBundle);
        SendMessageRequest aliceReq = aliceSessionMgr.prepareOutgoingMessage("bob", "Secret info", ephemeralKem, 1L);

        // Tamper with ciphertext
        byte[] rawCiphertext = Base64.getDecoder().decode(aliceReq.ciphertext());
        rawCiphertext[0] ^= 0xFF; // flip bits
        String tamperedCiphertext = Base64.getEncoder().encodeToString(rawCiphertext);

        String aliceIdKeyB64 = Base64.getEncoder().encodeToString(aliceKeystore.getIdentityKey().publicKey());
        EncryptedMessageDto tamperedMsg = new EncryptedMessageDto(
                103L, aliceReq.messageId(), 1L, "alice", 2L, "bob",
                tamperedCiphertext, aliceReq.nonce(), aliceReq.ephemeralKemCiphertext(),
                aliceReq.signature(), aliceReq.sequenceNumber(), "SENT", Instant.now(), null, null
        );

        assertThrows(CryptoException.class, () -> bobSessionMgr.processIncomingMessage(tamperedMsg, aliceIdKeyB64));
    }

    @Test
    @DisplayName("Should reject message when digital signature is forged")
    void testSignatureForgeryRejected() throws Exception {
        String bobIdKeyB64 = Base64.getEncoder().encodeToString(bobKeystore.getIdentityKey().publicKey());
        String bobSpkB64 = Base64.getEncoder().encodeToString(bobKeystore.getSignedPrekey().publicKey());
        String bobSpkSigB64 = Base64.getEncoder().encodeToString(bobKeystore.getSignedPrekeySignature());

        KeyExchangeBundleDto bobBundle = new KeyExchangeBundleDto(
                2L, "bob",
                bobIdKeyB64, "ML-DSA-65",
                bobSpkB64, "ML-KEM-768",
                bobSpkSigB64,
                null, null, null,
                1
        );

        String ephemeralKem = aliceSessionMgr.initiateSession("bob", bobBundle);
        SendMessageRequest aliceReq = aliceSessionMgr.prepareOutgoingMessage("bob", "Secret info", ephemeralKem, 1L);

        // Forged signature
        byte[] badSig = new byte[Base64.getDecoder().decode(aliceReq.signature()).length];
        String badSigB64 = Base64.getEncoder().encodeToString(badSig);

        String aliceIdKeyB64 = Base64.getEncoder().encodeToString(aliceKeystore.getIdentityKey().publicKey());
        EncryptedMessageDto forgedMsg = new EncryptedMessageDto(
                104L, aliceReq.messageId(), 1L, "alice", 2L, "bob",
                aliceReq.ciphertext(), aliceReq.nonce(), aliceReq.ephemeralKemCiphertext(),
                badSigB64, aliceReq.sequenceNumber(), "SENT", Instant.now(), null, null
        );

        assertThrows(CryptoException.class, () -> bobSessionMgr.processIncomingMessage(forgedMsg, aliceIdKeyB64));
    }
}
