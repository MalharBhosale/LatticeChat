package com.securechat.server.service;

import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.dto.KeyExchangeBundleDto;
import com.securechat.common.dto.OneTimePrekeyUploadDto;
import com.securechat.common.dto.PrekeyCountResponse;
import com.securechat.common.dto.PublishKeyBundleRequest;
import com.securechat.common.dto.UploadPrekeysRequest;
import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.AuditLogEntity;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.entity.UserKeyBundleEntity;
import com.securechat.server.entity.UserStatus;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.MessageRepository;
import com.securechat.server.repository.OneTimePrekeyRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
import com.securechat.server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class KeyManagementServiceTest {

    @Autowired
    private KeyManagementService keyManagementService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserKeyBundleRepository keyBundleRepository;

    @Autowired
    private OneTimePrekeyRepository prekeyRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private MessageRepository messageRepository;

    private final MlDsaSignatureService dsaService = new MlDsaSignatureService();
    private final MlKemKeyExchangeService kemService = new MlKemKeyExchangeService();

    private UserEntity bobUser;

    @BeforeEach
    void setUp() {
        messageRepository.deleteAll();
        prekeyRepository.deleteAll();
        keyBundleRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        bobUser = new UserEntity("bob", "bob@latticechat.internal", "passwordHash123", "Bob");
        bobUser.setStatus(UserStatus.ACTIVE);
        bobUser = userRepository.save(bobUser);
    }

    @Test
    @DisplayName("Should publish valid PQC key bundle with ML-DSA signature over ML-KEM prekey")
    void testPublishKeyBundleValidSignature() {
        SignatureKeyPair identityPair = dsaService.generateKeyPair();
        KemKeyPair prekeyPair = kemService.generateKeyPair();

        byte[] prekeyBytes = prekeyPair.publicKey();
        byte[] sigBytes = dsaService.sign(prekeyBytes, identityPair.privateKey());

        String idKeyB64 = Base64.getEncoder().encodeToString(identityPair.publicKey());
        String prekeyB64 = Base64.getEncoder().encodeToString(prekeyBytes);
        String sigB64 = Base64.getEncoder().encodeToString(sigBytes);

        KemKeyPair opkPair1 = kemService.generateKeyPair();
        String opk1B64 = Base64.getEncoder().encodeToString(opkPair1.publicKey());

        PublishKeyBundleRequest request = new PublishKeyBundleRequest(
                idKeyB64,
                "ML-DSA-65",
                prekeyB64,
                "ML-KEM-768",
                sigB64,
                List.of(new OneTimePrekeyUploadDto(101, opk1B64, "ML-KEM-768"))
        );

        UserKeyBundleEntity bundle = keyManagementService.publishKeyBundle("bob", request);

        assertNotNull(bundle.getId());
        assertEquals(1, bundle.getKeyVersion());
        assertTrue(bundle.getIsActive());
        assertEquals("ML-DSA-65", bundle.getIdentityAlgorithm());
        assertEquals("ML-KEM-768", bundle.getPrekeyAlgorithm());

        assertEquals(1, prekeyRepository.countByUserIdAndIsConsumedFalse(bobUser.getId()));

        List<AuditLogEntity> logs = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(AuditEventType.KEY_UPLOAD);
        assertFalse(logs.isEmpty());
    }

    @Test
    @DisplayName("Should reject bundle publication when prekey signature is invalid")
    void testPublishKeyBundleInvalidSignature() {
        SignatureKeyPair identityPair = dsaService.generateKeyPair();
        SignatureKeyPair otherPair = dsaService.generateKeyPair(); // Signed with different key!
        KemKeyPair prekeyPair = kemService.generateKeyPair();

        byte[] prekeyBytes = prekeyPair.publicKey();
        byte[] badSig = dsaService.sign(prekeyBytes, otherPair.privateKey());

        String idKeyB64 = Base64.getEncoder().encodeToString(identityPair.publicKey());
        String prekeyB64 = Base64.getEncoder().encodeToString(prekeyBytes);
        String badSigB64 = Base64.getEncoder().encodeToString(badSig);

        PublishKeyBundleRequest request = new PublishKeyBundleRequest(
                idKeyB64,
                "ML-DSA-65",
                prekeyB64,
                "ML-KEM-768",
                badSigB64,
                null
        );

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                keyManagementService.publishKeyBundle("bob", request));
        assertTrue(ex.getMessage().contains("Invalid prekey signature"));

        List<AuditLogEntity> failedLogs = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(AuditEventType.SIGNATURE_VERIFICATION_FAILED);
        assertFalse(failedLogs.isEmpty());
    }

    @Test
    @DisplayName("Should deactivate old bundle and increment version on bundle rotation")
    void testKeyBundleRotation() {
        // Publish Bundle v1
        SignatureKeyPair idPair1 = dsaService.generateKeyPair();
        KemKeyPair prekeyPair1 = kemService.generateKeyPair();
        byte[] sig1 = dsaService.sign(prekeyPair1.publicKey(), idPair1.privateKey());

        PublishKeyBundleRequest req1 = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(idPair1.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(prekeyPair1.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig1),
                null
        );
        UserKeyBundleEntity b1 = keyManagementService.publishKeyBundle("bob", req1);
        assertEquals(1, b1.getKeyVersion());

        // Publish Bundle v2 (Rotation)
        SignatureKeyPair idPair2 = dsaService.generateKeyPair();
        KemKeyPair prekeyPair2 = kemService.generateKeyPair();
        byte[] sig2 = dsaService.sign(prekeyPair2.publicKey(), idPair2.privateKey());

        PublishKeyBundleRequest req2 = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(idPair2.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(prekeyPair2.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig2),
                null
        );
        UserKeyBundleEntity b2 = keyManagementService.publishKeyBundle("bob", req2);
        assertEquals(2, b2.getKeyVersion());

        // Verify active bundle is v2
        UserKeyBundleEntity active = keyBundleRepository.findByUserIdAndIsActiveTrue(bobUser.getId()).orElseThrow();
        assertEquals(2, active.getKeyVersion());
        assertEquals(b2.getId(), active.getId());

        // Verify old bundle is deactivated
        UserKeyBundleEntity old = keyBundleRepository.findById(b1.getId()).orElseThrow();
        assertFalse(old.getIsActive());

        List<AuditLogEntity> rotationLogs = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(AuditEventType.KEY_ROTATION);
        assertFalse(rotationLogs.isEmpty());
    }

    @Test
    @DisplayName("Should claim one-time prekeys in strict FIFO order and handle exhaustion gracefully")
    void testClaimOneTimePrekeyFifo() {
        SignatureKeyPair idPair = dsaService.generateKeyPair();
        KemKeyPair prekeyPair = kemService.generateKeyPair();
        byte[] sig = dsaService.sign(prekeyPair.publicKey(), idPair.privateKey());

        KemKeyPair opk1 = kemService.generateKeyPair();
        KemKeyPair opk2 = kemService.generateKeyPair();

        PublishKeyBundleRequest request = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(idPair.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(prekeyPair.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig),
                List.of(
                        new OneTimePrekeyUploadDto(201, Base64.getEncoder().encodeToString(opk1.publicKey()), "ML-KEM-768"),
                        new OneTimePrekeyUploadDto(202, Base64.getEncoder().encodeToString(opk2.publicKey()), "ML-KEM-768")
                )
        );

        keyManagementService.publishKeyBundle("bob", request);

        // First discovery: Claims OPK 201
        KeyExchangeBundleDto bundle1 = keyManagementService.getKeyExchangeBundle("bob");
        assertEquals(201, bundle1.oneTimePrekeyId());
        assertNotNull(bundle1.oneTimePrekey());

        // Second discovery: Claims OPK 202
        KeyExchangeBundleDto bundle2 = keyManagementService.getKeyExchangeBundle("bob");
        assertEquals(202, bundle2.oneTimePrekeyId());
        assertNotNull(bundle2.oneTimePrekey());

        // Third discovery: OPKs are exhausted, gracefully returns signed prekey with null OPK
        KeyExchangeBundleDto bundle3 = keyManagementService.getKeyExchangeBundle("bob");
        assertNull(bundle3.oneTimePrekeyId());
        assertNull(bundle3.oneTimePrekey());
        assertNotNull(bundle3.signedPrekey()); // Signed prekey is always present
    }

    @Test
    @DisplayName("Should replenish one-time prekeys and report low stock status accurately")
    void testUploadPrekeysAndCount() {
        PrekeyCountResponse initial = keyManagementService.getPrekeyCount("bob");
        assertEquals(0, initial.remainingCount());
        assertTrue(initial.lowStock());

        // Upload 6 prekeys
        KemKeyPair k1 = kemService.generateKeyPair();
        UploadPrekeysRequest uploadReq = new UploadPrekeysRequest(
                List.of(
                        new OneTimePrekeyUploadDto(1, Base64.getEncoder().encodeToString(k1.publicKey()), "ML-KEM-768"),
                        new OneTimePrekeyUploadDto(2, Base64.getEncoder().encodeToString(k1.publicKey()), "ML-KEM-768"),
                        new OneTimePrekeyUploadDto(3, Base64.getEncoder().encodeToString(k1.publicKey()), "ML-KEM-768"),
                        new OneTimePrekeyUploadDto(4, Base64.getEncoder().encodeToString(k1.publicKey()), "ML-KEM-768"),
                        new OneTimePrekeyUploadDto(5, Base64.getEncoder().encodeToString(k1.publicKey()), "ML-KEM-768"),
                        new OneTimePrekeyUploadDto(6, Base64.getEncoder().encodeToString(k1.publicKey()), "ML-KEM-768")
                )
        );

        int added = keyManagementService.uploadOneTimePrekeys("bob", uploadReq);
        assertEquals(6, added);

        PrekeyCountResponse updated = keyManagementService.getPrekeyCount("bob");
        assertEquals(6, updated.remainingCount());
        assertFalse(updated.lowStock()); // >= 5 is not low stock
    }
}
