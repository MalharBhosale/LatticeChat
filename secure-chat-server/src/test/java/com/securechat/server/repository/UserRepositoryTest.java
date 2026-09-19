package com.securechat.server.repository;

import com.securechat.server.entity.UserEntity;
import com.securechat.server.entity.UserStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DataJpaTest
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TestEntityManager entityManager;

    @Test
    @DisplayName("Should persist user and find by username and email")
    void testSaveAndFindUser() {
        UserEntity user = new UserEntity(
                "alice",
                "alice@latticechat.internal",
                "$2a$10$hashedPasswordHereExample1234567890",
                "Alice Quantum"
        );

        UserEntity saved = userRepository.save(user);
        assertNotNull(saved.getId());
        assertNotNull(saved.getCreatedAt());
        assertNotNull(saved.getUpdatedAt());
        assertEquals(UserStatus.ACTIVE, saved.getStatus());

        Optional<UserEntity> byUsername = userRepository.findByUsername("alice");
        assertTrue(byUsername.isPresent());
        assertEquals("alice@latticechat.internal", byUsername.get().getEmail());

        Optional<UserEntity> byEmail = userRepository.findByEmail("alice@latticechat.internal");
        assertTrue(byEmail.isPresent());
        assertEquals("alice", byEmail.get().getUsername());

        assertTrue(userRepository.existsByUsername("alice"));
        assertTrue(userRepository.existsByEmail("alice@latticechat.internal"));
        assertFalse(userRepository.existsByUsername("unknown_user"));
    }

    @Test
    @DisplayName("Should enforce unique username constraint")
    void testUniqueUsernameConstraint() {
        UserEntity user1 = new UserEntity("bob", "bob1@latticechat.internal", "hash1", "Bob 1");
        userRepository.saveAndFlush(user1);

        UserEntity user2 = new UserEntity("bob", "bob2@latticechat.internal", "hash2", "Bob 2");
        assertThrows(DataIntegrityViolationException.class, () -> {
            userRepository.saveAndFlush(user2);
        });
    }

    @Test
    @DisplayName("Should enforce unique email constraint")
    void testUniqueEmailConstraint() {
        UserEntity user1 = new UserEntity("charlie1", "charlie@latticechat.internal", "hash1", "Charlie 1");
        userRepository.saveAndFlush(user1);

        UserEntity user2 = new UserEntity("charlie2", "charlie@latticechat.internal", "hash2", "Charlie 2");
        assertThrows(DataIntegrityViolationException.class, () -> {
            userRepository.saveAndFlush(user2);
        });
    }

    @Test
    @DisplayName("Should find users by status")
    void testFindByStatus() {
        UserEntity active = new UserEntity("dave", "dave@latticechat.internal", "hash", "Dave");
        UserEntity suspended = new UserEntity("eve", "eve@latticechat.internal", "hash", "Eve");
        suspended.setStatus(UserStatus.SUSPENDED);

        userRepository.save(active);
        userRepository.save(suspended);

        List<UserEntity> activeUsers = userRepository.findByStatus(UserStatus.ACTIVE);
        assertTrue(activeUsers.stream().anyMatch(u -> u.getUsername().equals("dave")));
        assertFalse(activeUsers.stream().anyMatch(u -> u.getUsername().equals("eve")));
    }
}
