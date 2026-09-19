package com.securechat.server.repository;

import com.securechat.server.entity.OneTimePrekeyEntity;
import com.securechat.server.entity.UserEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DataJpaTest
@ActiveProfiles("test")
class OneTimePrekeyRepositoryTest {

    @Autowired
    private OneTimePrekeyRepository prekeyRepository;

    @Autowired
    private UserRepository userRepository;

    private UserEntity bob;

    @BeforeEach
    void setUp() {
        bob = userRepository.save(new UserEntity(
                "bob_otk",
                "bob_otk@latticechat.internal",
                "hashBob123",
                "Bob OTK"
        ));
    }

    @Test
    @DisplayName("Should claim and consume one-time prekeys in FIFO order")
    void testClaimAndConsumeOneTimePrekey() {
        // Save two one-time prekeys for Bob
        OneTimePrekeyEntity otk1 = new OneTimePrekeyEntity(bob, 101, "OTK_KEY_101_BYTES", "ML-KEM-768");
        OneTimePrekeyEntity otk2 = new OneTimePrekeyEntity(bob, 102, "OTK_KEY_102_BYTES", "ML-KEM-768");

        prekeyRepository.save(otk1);
        prekeyRepository.save(otk2);

        assertEquals(2, prekeyRepository.countByUserIdAndIsConsumedFalse(bob.getId()));

        // Claim first prekey
        Optional<OneTimePrekeyEntity> claimed1 = prekeyRepository.findFirstByUserIdAndIsConsumedFalseOrderByIdAsc(bob.getId());
        assertTrue(claimed1.isPresent());
        assertEquals(101, claimed1.get().getKeyId());

        // Mark as consumed
        claimed1.get().markConsumed();
        prekeyRepository.save(claimed1.get());

        // Verify remaining count
        assertEquals(1, prekeyRepository.countByUserIdAndIsConsumedFalse(bob.getId()));

        // Claim second prekey
        Optional<OneTimePrekeyEntity> claimed2 = prekeyRepository.findFirstByUserIdAndIsConsumedFalseOrderByIdAsc(bob.getId());
        assertTrue(claimed2.isPresent());
        assertEquals(102, claimed2.get().getKeyId());

        claimed2.get().markConsumed();
        prekeyRepository.save(claimed2.get());

        // Verify all consumed
        assertEquals(0, prekeyRepository.countByUserIdAndIsConsumedFalse(bob.getId()));
        Optional<OneTimePrekeyEntity> noneLeft = prekeyRepository.findFirstByUserIdAndIsConsumedFalseOrderByIdAsc(bob.getId());
        assertFalse(noneLeft.isPresent());
    }
}
