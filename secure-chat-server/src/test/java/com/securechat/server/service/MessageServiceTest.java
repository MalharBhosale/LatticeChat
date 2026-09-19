package com.securechat.server.service;

import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.dto.EncryptedMessageDto;
import com.securechat.common.dto.PublishKeyBundleRequest;
import com.securechat.common.dto.SendMessageRequest;
import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.AuditLogEntity;
import com.securechat.server.entity.MessageEntity;
import com.securechat.server.entity.MessageStatus;
import com.securechat.server.entity.UserEntity;
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class MessageServiceTest {

    @Autowired
    private MessageService messageService;

    @Autowired
    private KeyManagementService keyManagementService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserKeyBundleRepository keyBundleRepository;

    @Autowired
    private OneTimePrekeyRepository prekeyRepository;

    @Autowired
    private MessageRepository messageRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    private final MlDsaSignatureService dsaService = new MlDsaSignatureService();
    private final MlKemKeyExchangeService kemService = new MlKemKeyExchangeService();

    private UserEntity aliceUser;
    private UserEntity bobUser;
    private SignatureKeyPair aliceDsaPair;

    @BeforeEach
    void setUp() {
        messageRepository.deleteAll();
        prekeyRepository.deleteAll();
        keyBundleRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        aliceUser = userRepository.save(new UserEntity("alice", "alice@latticechat.internal", "hashA", "Alice"));
        bobUser = userRepository.save(new UserEntity("bob", "bob@latticechat.internal", "hashB", "Bob"));
        aliceUser.setStatus(UserStatus.ACTIVE);
        bobUser.setStatus(UserStatus.ACTIVE);

        // Setup Alice's key bundle
        aliceDsaPair = dsaService.generateKeyPair();
        KemKeyPair aliceKemPair = kemService.generateKeyPair();
        byte[] aliceSig = dsaService.sign(aliceKemPair.publicKey(), aliceDsaPair.privateKey());

        keyManagementService.publishKeyBundle("alice", new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(aliceDsaPair.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(aliceKemPair.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(aliceSig),
                null
        ));
    }

    @Test
    @DisplayName("Should transmit encrypted message and record MESSAGE_SENT audit event")
    void testSendMessageSuccess() {
        String msgId = UUID.randomUUID().toString();
        long seq = 1L;
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]);
        String ciphertextB64 = Base64.getEncoder().encodeToString("SuperSecretPostQuantumPayload".getBytes(StandardCharsets.UTF_8));

        String payload = MessageService.buildPayloadString(msgId, seq, nonceB64, ciphertextB64);
        byte[] sig = dsaService.sign(payload.getBytes(StandardCharsets.UTF_8), aliceDsaPair.privateKey());
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        SendMessageRequest request = new SendMessageRequest("bob", msgId, ciphertextB64, nonceB64, null, sigB64, seq);
        EncryptedMessageDto response = messageService.sendMessage("alice", request);

        assertNotNull(response.id());
        assertEquals(msgId, response.messageId());
        assertEquals("alice", response.senderUsername());
        assertEquals("bob", response.recipientUsername());
        assertEquals("SENT", response.status());

        MessageEntity saved = messageRepository.findByMessageId(msgId).orElseThrow();
        assertEquals(MessageStatus.SENT, saved.getStatus());

        List<AuditLogEntity> logs = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(AuditEventType.MESSAGE_SENT);
        assertFalse(logs.isEmpty());
    }

    @Test
    @DisplayName("Should detect replay attack when duplicate messageId is transmitted")
    void testReplayAttackRejected() {
        String msgId = "replay-uuid-001";
        long seq = 1L;
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]);
        String ciphertextB64 = Base64.getEncoder().encodeToString("Data".getBytes(StandardCharsets.UTF_8));

        String payload = MessageService.buildPayloadString(msgId, seq, nonceB64, ciphertextB64);
        byte[] sig = dsaService.sign(payload.getBytes(StandardCharsets.UTF_8), aliceDsaPair.privateKey());
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        SendMessageRequest req1 = new SendMessageRequest("bob", msgId, ciphertextB64, nonceB64, null, sigB64, seq);
        messageService.sendMessage("alice", req1);

        // Attempt duplicate replay with same messageId
        SendMessageRequest req2 = new SendMessageRequest("bob", msgId, ciphertextB64, nonceB64, null, sigB64, 2L);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                messageService.sendMessage("alice", req2));
        assertTrue(ex.getMessage().contains("replay attack"));

        List<AuditLogEntity> replayLogs = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(AuditEventType.REPLAY_ATTACK_DETECTED);
        assertFalse(replayLogs.isEmpty());
    }

    @Test
    @DisplayName("Should reject message when ML-DSA digital signature is tampered with")
    void testInvalidSignatureRejected() {
        String msgId = UUID.randomUUID().toString();
        long seq = 1L;
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]);
        String ciphertextB64 = Base64.getEncoder().encodeToString("OriginalPayload".getBytes(StandardCharsets.UTF_8));

        // Sign original payload
        String payload = MessageService.buildPayloadString(msgId, seq, nonceB64, ciphertextB64);
        byte[] sig = dsaService.sign(payload.getBytes(StandardCharsets.UTF_8), aliceDsaPair.privateKey());
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        // Attacker alters ciphertext in transit
        String tamperedCiphertext = Base64.getEncoder().encodeToString("TamperedPayload".getBytes(StandardCharsets.UTF_8));
        SendMessageRequest tamperedReq = new SendMessageRequest("bob", msgId, tamperedCiphertext, nonceB64, null, sigB64, seq);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                messageService.sendMessage("alice", tamperedReq));
        assertTrue(ex.getMessage().contains("sender authentication failed"));

        List<AuditLogEntity> failedLogs = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(AuditEventType.SIGNATURE_VERIFICATION_FAILED);
        assertFalse(failedLogs.isEmpty());
    }

    @Test
    @DisplayName("Should retrieve pending messages and automatically transition them to DELIVERED")
    void testGetPendingMessagesDelivered() {
        // Send message from Alice to Bob
        String msgId = UUID.randomUUID().toString();
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]);
        String ctB64 = Base64.getEncoder().encodeToString("Message 1".getBytes(StandardCharsets.UTF_8));
        String sig = Base64.getEncoder().encodeToString(dsaService.sign(
                MessageService.buildPayloadString(msgId, 1L, nonceB64, ctB64).getBytes(StandardCharsets.UTF_8),
                aliceDsaPair.privateKey()));

        messageService.sendMessage("alice", new SendMessageRequest("bob", msgId, ctB64, nonceB64, null, sig, 1L));

        // Bob polls pending messages
        List<EncryptedMessageDto> pending = messageService.getPendingMessages("bob");
        assertEquals(1, pending.size());
        assertEquals("DELIVERED", pending.get(0).status());
        assertNotNull(pending.get(0).deliveredAt());

        // Subsequent poll returns empty list (all delivered)
        List<EncryptedMessageDto> pendingAgain = messageService.getPendingMessages("bob");
        assertTrue(pendingAgain.isEmpty());

        List<AuditLogEntity> delivLogs = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(AuditEventType.MESSAGE_DELIVERED);
        assertFalse(delivLogs.isEmpty());
    }

    @Test
    @DisplayName("Should update message status to READ upon delivery receipt")
    void testUpdateMessageStatusRead() {
        String msgId = UUID.randomUUID().toString();
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]);
        String ctB64 = Base64.getEncoder().encodeToString("ReadMe".getBytes(StandardCharsets.UTF_8));
        String sig = Base64.getEncoder().encodeToString(dsaService.sign(
                MessageService.buildPayloadString(msgId, 1L, nonceB64, ctB64).getBytes(StandardCharsets.UTF_8),
                aliceDsaPair.privateKey()));

        messageService.sendMessage("alice", new SendMessageRequest("bob", msgId, ctB64, nonceB64, null, sig, 1L));

        EncryptedMessageDto updated = messageService.updateMessageStatus("bob", msgId, MessageStatus.READ);
        assertEquals("READ", updated.status());
        assertNotNull(updated.readAt());
    }

    @Test
    @DisplayName("Should retrieve full conversation history between peers in chronological order")
    void testGetConversationHistory() {
        // Alice sends 2 messages to Bob
        for (int i = 1; i <= 2; i++) {
            String msgId = UUID.randomUUID().toString();
            String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]);
            String ctB64 = Base64.getEncoder().encodeToString(("Msg " + i).getBytes(StandardCharsets.UTF_8));
            String sig = Base64.getEncoder().encodeToString(dsaService.sign(
                    MessageService.buildPayloadString(msgId, (long) i, nonceB64, ctB64).getBytes(StandardCharsets.UTF_8),
                    aliceDsaPair.privateKey()));
            messageService.sendMessage("alice", new SendMessageRequest("bob", msgId, ctB64, nonceB64, null, sig, (long) i));
        }

        List<EncryptedMessageDto> history = messageService.getConversationHistory("alice", "bob");
        assertEquals(2, history.size());
        assertEquals(1L, history.get(0).sequenceNumber());
        assertEquals(2L, history.get(1).sequenceNumber());
    }
}
