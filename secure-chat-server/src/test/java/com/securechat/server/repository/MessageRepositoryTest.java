package com.securechat.server.repository;

import com.securechat.server.entity.MessageEntity;
import com.securechat.server.entity.MessageStatus;
import com.securechat.server.entity.UserEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DataJpaTest
@ActiveProfiles("test")
class MessageRepositoryTest {

    @Autowired
    private MessageRepository messageRepository;

    @Autowired
    private UserRepository userRepository;

    private UserEntity alice;
    private UserEntity bob;

    @BeforeEach
    void setUp() {
        alice = userRepository.save(new UserEntity("alice_msg", "alice_msg@latticechat.internal", "hashA", "Alice"));
        bob = userRepository.save(new UserEntity("bob_msg", "bob_msg@latticechat.internal", "hashB", "Bob"));
    }

    @Test
    @DisplayName("Should persist zero-knowledge encrypted message with delivery tracking")
    void testSaveAndRetrieveMessage() {
        String messageId = UUID.randomUUID().toString();
        String mockCiphertext = "U2FsdGVkX1+...ENCRYPTED_PAYLOAD_AES_256_GCM...";
        String mockNonce = "96_BIT_NONCE_BASE64";
        String mockSignature = "ML_DSA_65_DIGITAL_SIGNATURE_OVER_CIPHERTEXT";

        MessageEntity message = new MessageEntity(
                messageId,
                alice,
                bob,
                mockCiphertext,
                mockNonce,
                mockSignature,
                1L
        );
        message.setEphemeralKemCiphertext("EPHEMERAL_ML_KEM_CIPHERTEXT_1088_BYTES");

        MessageEntity saved = messageRepository.save(message);
        assertNotNull(saved.getId());
        assertEquals(MessageStatus.SENT, saved.getStatus());
        assertNotNull(saved.getSentAt());

        // Find by message UUID
        Optional<MessageEntity> byId = messageRepository.findByMessageId(messageId);
        assertTrue(byId.isPresent());
        assertEquals(alice.getId(), byId.get().getSender().getId());
        assertEquals(bob.getId(), byId.get().getRecipient().getId());

        // Query pending messages for Bob
        List<MessageEntity> pending = messageRepository.findByRecipientIdAndStatusOrderBySentAtAsc(bob.getId(), MessageStatus.SENT);
        assertEquals(1, pending.size());
        assertEquals(messageId, pending.get(0).getMessageId());

        // Update status to DELIVERED
        pending.get(0).markDelivered();
        messageRepository.save(pending.get(0));

        List<MessageEntity> pendingAfter = messageRepository.findByRecipientIdAndStatusOrderBySentAtAsc(bob.getId(), MessageStatus.SENT);
        assertEquals(0, pendingAfter.size());
    }

    @Test
    @DisplayName("Should retrieve full bidirectional conversation history between two users")
    void testFindConversationBetweenUsers() {
        MessageEntity msg1 = new MessageEntity(UUID.randomUUID().toString(), alice, bob, "CIPHERTEXT_1", "NONCE_1", "SIG_1", 1L);
        MessageEntity msg2 = new MessageEntity(UUID.randomUUID().toString(), bob, alice, "CIPHERTEXT_2", "NONCE_2", "SIG_2", 1L);
        MessageEntity msg3 = new MessageEntity(UUID.randomUUID().toString(), alice, bob, "CIPHERTEXT_3", "NONCE_3", "SIG_3", 2L);

        messageRepository.save(msg1);
        messageRepository.save(msg2);
        messageRepository.save(msg3);

        List<MessageEntity> conversation = messageRepository.findConversationBetweenUsers(alice.getId(), bob.getId());
        assertEquals(3, conversation.size());
    }
}
