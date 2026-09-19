package com.securechat.server.repository;

import com.securechat.server.entity.UserEntity;
import com.securechat.server.entity.UserKeyBundleEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DataJpaTest
@ActiveProfiles("test")
class UserKeyBundleRepositoryTest {

    @Autowired
    private UserKeyBundleRepository keyBundleRepository;

    @Autowired
    private UserRepository userRepository;

    private UserEntity testUser;

    @BeforeEach
    void setUp() {
        testUser = userRepository.save(new UserEntity(
                "alice_crypto",
                "alice_crypto@latticechat.internal",
                "hash123",
                "Alice PQC"
        ));
    }

    @Test
    @DisplayName("Should persist and retrieve active Post-Quantum Key Bundle")
    void testSaveAndFindActiveBundle() {
        String mockMldsaPublicKey = "BASE64_MOCK_ML_DSA_65_PUBLIC_KEY_CONTENT_EXTENDED_BYTES_1952";
        String mockMlkemPrekey = "BASE64_MOCK_ML_KEM_768_PREKEY_CONTENT_EXTENDED_BYTES_1184";
        String mockSignature = "BASE64_MOCK_ML_DSA_65_SIGNATURE_OVER_PREKEY_3309";

        UserKeyBundleEntity bundle = new UserKeyBundleEntity(
                testUser,
                mockMldsaPublicKey,
                "ML-DSA-65",
                mockMlkemPrekey,
                "ML-KEM-768",
                mockSignature,
                1
        );

        UserKeyBundleEntity saved = keyBundleRepository.save(bundle);
        assertNotNull(saved.getId());
        assertNotNull(saved.getCreatedAt());
        assertTrue(saved.getIsActive());

        Optional<UserKeyBundleEntity> activeBundle = keyBundleRepository.findByUserIdAndIsActiveTrue(testUser.getId());
        assertTrue(activeBundle.isPresent());
        assertEquals("ML-DSA-65", activeBundle.get().getIdentityAlgorithm());
        assertEquals("ML-KEM-768", activeBundle.get().getPrekeyAlgorithm());
        assertEquals(mockMldsaPublicKey, activeBundle.get().getIdentityKey());

        Optional<UserKeyBundleEntity> byUsername = keyBundleRepository.findByUserUsernameAndIsActiveTrue("alice_crypto");
        assertTrue(byUsername.isPresent());
        assertEquals(saved.getId(), byUsername.get().getId());
    }

    @Test
    @DisplayName("Should support key rotation and deactivating previous bundles")
    void testKeyRotation() {
        UserKeyBundleEntity bundleV1 = new UserKeyBundleEntity(
                testUser, "DSA_KEY_V1", "ML-DSA-65", "KEM_KEY_V1", "ML-KEM-768", "SIG_V1", 1
        );
        keyBundleRepository.save(bundleV1);

        // Deactivate all previous keys for user
        keyBundleRepository.deactivateAllByUserId(testUser.getId());

        // Upload new V2 bundle
        UserKeyBundleEntity bundleV2 = new UserKeyBundleEntity(
                testUser, "DSA_KEY_V2", "ML-DSA-65", "KEM_KEY_V2", "ML-KEM-768", "SIG_V2", 2
        );
        keyBundleRepository.save(bundleV2);

        Optional<UserKeyBundleEntity> active = keyBundleRepository.findByUserIdAndIsActiveTrue(testUser.getId());
        assertTrue(active.isPresent());
        assertEquals(2, active.get().getKeyVersion());
        assertEquals("DSA_KEY_V2", active.get().getIdentityKey());

        List<UserKeyBundleEntity> allBundles = keyBundleRepository.findAllByUserIdOrderByKeyVersionDesc(testUser.getId());
        assertEquals(2, allBundles.size());
        assertEquals(2, allBundles.get(0).getKeyVersion());
        assertEquals(1, allBundles.get(1).getKeyVersion());
        assertFalse(allBundles.get(1).getIsActive());
    }
}
