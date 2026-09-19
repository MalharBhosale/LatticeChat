package com.securechat.server.service;

import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.dto.KeyExchangeBundleDto;
import com.securechat.common.dto.OneTimePrekeyUploadDto;
import com.securechat.common.dto.PublishKeyBundleRequest;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.entity.UserStatus;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.OneTimePrekeyRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
import com.securechat.server.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.*;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Concurrency stress test verifying that high-throughput, simultaneous one-time prekey (OPK)
 * claims never double-allocate or corrupt the prekey pool under race conditions.
 */
@SpringBootTest
@ActiveProfiles("test")
class ConcurrentPrekeyClaimStressTest {

    @Autowired
    private KeyManagementService keyManagementService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserKeyBundleRepository keyBundleRepository;

    @Autowired
    private OneTimePrekeyRepository prekeyRepository;

    @Autowired
    private com.securechat.server.repository.MessageRepository messageRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    private final MlKemKeyExchangeService kem = MlKemKeyExchangeService.mlKem768();
    private final MlDsaSignatureService dsa = MlDsaSignatureService.mlDsa65();

    private static final String BOB_USERNAME = "bob_prekey_stress";

    @BeforeEach
    void setUp() {
        tearDown();

        UserEntity bob = new UserEntity(BOB_USERNAME, "bob_stress@example.com", "$2a$12$dummyHashedPasswordForStressTestingBob012345", "Bob Stress");
        bob.setStatus(UserStatus.ACTIVE);
        userRepository.save(bob);

        // Generate Bob's identity and signed prekey
        SignatureKeyPair idKp = dsa.generateKeyPair();
        KemKeyPair spkKp = kem.generateKeyPair();
        byte[] spkSig = dsa.sign(spkKp.publicKey(), idKp.privateKey());

        // Prepare exactly 10 one-time prekeys
        List<OneTimePrekeyUploadDto> opks = new ArrayList<>();
        for (int i = 1; i <= 10; i++) {
            KemKeyPair opkKp = kem.generateKeyPair();
            opks.add(new OneTimePrekeyUploadDto(
                    i,
                    Base64.getEncoder().encodeToString(opkKp.publicKey()),
                    "ML-KEM-768"
            ));
        }

        PublishKeyBundleRequest req = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(idKp.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(spkKp.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(spkSig),
                opks
        );

        keyManagementService.publishKeyBundle(BOB_USERNAME, req);
    }

    @AfterEach
    void tearDown() {
        messageRepository.deleteAll();
        prekeyRepository.deleteAll();
        keyBundleRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Stress Test: 15 concurrent threads claiming from 10 OPKs prevents race conditions & double-claims")
    void testConcurrentPrekeyClaimAtomicSemantics() throws Exception {
        int clientThreads = 15;
        ExecutorService executor = Executors.newFixedThreadPool(clientThreads);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch finishLatch = new CountDownLatch(clientThreads);

        ConcurrentLinkedQueue<KeyExchangeBundleDto> claimedBundles = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<Throwable> claimErrors = new ConcurrentLinkedQueue<>();

        for (int i = 0; i < clientThreads; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await(); // Synchronized stampede
                    KeyExchangeBundleDto bundle = keyManagementService.getKeyExchangeBundle(BOB_USERNAME);
                    claimedBundles.add(bundle);
                } catch (Throwable t) {
                    claimErrors.add(t);
                } finally {
                    finishLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean completed = finishLatch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertTrue(completed, "All prekey claiming threads must complete within timeout");
        assertTrue(claimErrors.isEmpty(), "Zero errors expected during concurrent OPK claiming, but got: " + claimErrors);
        assertEquals(clientThreads, claimedBundles.size());

        // Validate uniqueness of claimed OPKs
        Set<Integer> claimedOpkIds = new HashSet<>();
        int bundleWithOpkCount = 0;
        int bundleFallbackCount = 0;

        for (KeyExchangeBundleDto bundle : claimedBundles) {
            assertNotNull(bundle);
            assertNotNull(bundle.identityKey());
            assertNotNull(bundle.signedPrekey());

            if (bundle.oneTimePrekey() != null && bundle.oneTimePrekeyId() != null) {
                bundleWithOpkCount++;
                boolean isUnique = claimedOpkIds.add(bundle.oneTimePrekeyId());
                assertTrue(isUnique, "OPK ID " + bundle.oneTimePrekeyId() + " was double-claimed! Race condition detected.");
            } else {
                bundleFallbackCount++;
            }
        }

        // Exactly 10 OPKs were available, so 10 must be claimed uniquely, and 5 must gracefully fall back
        assertEquals(10, bundleWithOpkCount, "Exactly 10 bundles must have received an OPK");
        assertEquals(5, bundleFallbackCount, "Remaining 5 threads must fall back to SPK-only without error");
        assertEquals(10, claimedOpkIds.size(), "All 10 claimed OPKs must have distinct IDs");

        // Verify that database reflects 0 unconsumed OPKs remaining
        UserEntity bob = userRepository.findByUsername(BOB_USERNAME).orElseThrow();
        long unconsumedCount = prekeyRepository.countByUserIdAndIsConsumedFalse(bob.getId());
        assertEquals(0, unconsumedCount, "Zero unconsumed OPKs should remain in the database");
    }
}
