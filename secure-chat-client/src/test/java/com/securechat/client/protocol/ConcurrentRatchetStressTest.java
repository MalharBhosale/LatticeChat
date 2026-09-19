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
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * High-concurrency stress test suite for Post-Quantum Session ratcheting.
 * Verifies thread safety, absence of deadlocks, and message integrity under heavy parallel execution.
 */
class ConcurrentRatchetStressTest {

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
        aliceKeystore = ClientKeystore.generateNew(10);
        bobKeystore = ClientKeystore.generateNew(10);

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

    private void establishSession() throws Exception {
        String bobIdKeyB64 = Base64.getEncoder().encodeToString(bobKeystore.getIdentityKey().publicKey());
        String bobSpkB64 = Base64.getEncoder().encodeToString(bobKeystore.getSignedPrekey().publicKey());
        String bobSpkSigB64 = Base64.getEncoder().encodeToString(bobKeystore.getSignedPrekeySignature());
        String bobOpk1B64 = Base64.getEncoder().encodeToString(bobKeystore.getOneTimePrekey(1L).publicKey());

        KeyExchangeBundleDto bobBundle = new KeyExchangeBundleDto(
                1L, "bob",
                bobIdKeyB64, "ML-DSA-65",
                bobSpkB64, "ML-KEM-768",
                bobSpkSigB64,
                1, bobOpk1B64, "ML-KEM-768",
                1
        );

        String ephemeralKem = aliceSessionMgr.initiateSession("bob", bobBundle);

        String aliceIdKeyB64 = Base64.getEncoder().encodeToString(aliceKeystore.getIdentityKey().publicKey());

        // Initial handshake message from Alice to Bob
        SendMessageRequest initialReq = aliceSessionMgr.prepareOutgoingMessage(
                "bob",
                "Handshake init",
                ephemeralKem,
                1L
        );

        EncryptedMessageDto dto = new EncryptedMessageDto(
                1L,
                initialReq.messageId(),
                1L, "alice",
                2L, "bob",
                initialReq.ciphertext(),
                initialReq.nonce(),
                initialReq.ephemeralKemCiphertext(),
                initialReq.signature(),
                initialReq.sequenceNumber(),
                "DELIVERED",
                Instant.now(), null, null
        );

        bobSessionMgr.processIncomingMessage(dto, aliceIdKeyB64);
    }

    @Test
    @DisplayName("Stress Test: 20 concurrent threads encrypting and ratcheting messages without corruption")
    void testConcurrentMultiThreadedMessaging() throws Exception {
        establishSession();
        String aliceIdKeyB64 = Base64.getEncoder().encodeToString(aliceKeystore.getIdentityKey().publicKey());

        int threadCount = 20;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch finishLatch = new CountDownLatch(threadCount);

        ConcurrentLinkedQueue<SendMessageRequest> outgoingQueue = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        AtomicInteger seqGen = new AtomicInteger(2);

        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            executor.submit(() -> {
                try {
                    startLatch.await(); // Simultaneous trigger
                    String plaintext = "Concurrent post-quantum message #" + index;
                    SendMessageRequest req = aliceSessionMgr.prepareOutgoingMessage(
                            "bob",
                            plaintext,
                            null,
                            seqGen.getAndIncrement()
                    );
                    outgoingQueue.add(req);
                } catch (Throwable t) {
                    errors.add(t);
                } finally {
                    finishLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean completed = finishLatch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertTrue(completed, "All threads must finish within timeout");
        assertTrue(errors.isEmpty(), "Zero errors expected during concurrent encryption, but got: " + errors);
        assertEquals(threadCount, outgoingQueue.size());

        // Process all prepared messages through Bob's session manager
        long msgId = 100L;
        for (SendMessageRequest req : outgoingQueue) {
            EncryptedMessageDto dto = new EncryptedMessageDto(
                    ++msgId,
                    req.messageId(),
                    1L, "alice",
                    2L, "bob",
                    req.ciphertext(),
                    req.nonce(),
                    req.ephemeralKemCiphertext(),
                    req.signature(),
                    req.sequenceNumber(),
                    "DELIVERED",
                    Instant.now(), null, null
            );

            LocalMessage decrypted = bobSessionMgr.processIncomingMessage(dto, aliceIdKeyB64);
            assertNotNull(decrypted);
            assertTrue(decrypted.plaintext().startsWith("Concurrent post-quantum message #"));
        }
    }

    @Test
    @DisplayName("Stress Test: 100 rapid sequential symmetric ratchet steps verify deterministic progression")
    void testRapidSequentialRatchetProgression() throws Exception {
        establishSession();
        String aliceIdKeyB64 = Base64.getEncoder().encodeToString(aliceKeystore.getIdentityKey().publicKey());

        int iterations = 100;
        for (int i = 2; i <= iterations + 1; i++) {
            String original = "Rapid ratcheting message turn " + i;
            SendMessageRequest req = aliceSessionMgr.prepareOutgoingMessage(
                    "bob",
                    original,
                    null,
                    (long) i
            );

            EncryptedMessageDto dto = new EncryptedMessageDto(
                    (long) (1000 + i),
                    req.messageId(),
                    1L, "alice",
                    2L, "bob",
                    req.ciphertext(),
                    req.nonce(),
                    req.ephemeralKemCiphertext(),
                    req.signature(),
                    req.sequenceNumber(),
                    "DELIVERED",
                    Instant.now(), null, null
            );

            LocalMessage decrypted = bobSessionMgr.processIncomingMessage(dto, aliceIdKeyB64);
            assertEquals(original, decrypted.plaintext());
            assertEquals(req.sequenceNumber(), decrypted.sequenceNumber());
        }
    }
}
