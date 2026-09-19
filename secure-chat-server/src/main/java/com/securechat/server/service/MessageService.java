package com.securechat.server.service;

import com.securechat.common.crypto.SignatureService;
import com.securechat.common.dto.EncryptedMessageDto;
import com.securechat.common.dto.SendMessageRequest;
import com.securechat.common.exception.AuthorizationException;
import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.AuditLogEntity;
import com.securechat.server.entity.MessageEntity;
import com.securechat.server.entity.MessageStatus;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.entity.UserKeyBundleEntity;
import com.securechat.server.exception.ResourceNotFoundException;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.MessageRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
import com.securechat.server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/**
 * Service managing Zero-Knowledge End-to-End Encrypted messaging,
 * replay attack prevention, digital signature verification, and delivery receipts.
 */
@Service
public class MessageService {

    private static final Logger log = LoggerFactory.getLogger(MessageService.class);

    private final MessageRepository messageRepository;
    private final UserRepository userRepository;
    private final UserKeyBundleRepository userKeyBundleRepository;
    private final AuditLogRepository auditLogRepository;
    private final SignatureService signatureService;

    public MessageService(MessageRepository messageRepository,
                          UserRepository userRepository,
                          UserKeyBundleRepository userKeyBundleRepository,
                          AuditLogRepository auditLogRepository,
                          SignatureService signatureService) {
        this.messageRepository = messageRepository;
        this.userRepository = userRepository;
        this.userKeyBundleRepository = userKeyBundleRepository;
        this.auditLogRepository = auditLogRepository;
        this.signatureService = signatureService;
    }

    /**
     * Stores and relays an encrypted message.
     * Enforces replay attack defenses and cryptographically validates the sender's ML-DSA-65 signature.
     */
    @Transactional(noRollbackFor = IllegalArgumentException.class)
    public EncryptedMessageDto sendMessage(String senderUsername, SendMessageRequest request) {
        if (request == null || request.messageId() == null || request.recipientUsername() == null
                || request.ciphertext() == null || request.nonce() == null || request.signature() == null) {
            throw new IllegalArgumentException("Recipient, messageId, ciphertext, nonce, and signature are required");
        }

        // 1. Replay attack defense: Verify uniqueness of messageId
        if (messageRepository.existsByMessageId(request.messageId())) {
            UserEntity sender = userRepository.findByUsername(senderUsername).orElse(null);
            recordAuditLog(sender, AuditEventType.REPLAY_ATTACK_DETECTED,
                    "Duplicate message ID detected (replay attack): " + request.messageId());
            throw new IllegalArgumentException("Duplicate message ID: possible replay attack detected (" + request.messageId() + ")");
        }

        // 2. Fetch sender and recipient
        UserEntity sender = userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new ResourceNotFoundException("Sender '" + senderUsername + "' not found"));
        UserEntity recipient = userRepository.findByUsername(request.recipientUsername())
                .orElseThrow(() -> new ResourceNotFoundException("Recipient '" + request.recipientUsername() + "' not found"));

        // 3. Sender ML-DSA-65 digital signature verification
        UserKeyBundleEntity senderBundle = userKeyBundleRepository.findByUserIdAndIsActiveTrue(sender.getId())
                .orElseThrow(() -> new IllegalArgumentException("Sender '" + senderUsername + "' does not have an active public key bundle"));

        try {
            String payloadToVerify = buildPayloadString(request.messageId(), request.sequenceNumber(), request.nonce(), request.ciphertext());
            byte[] messageBytes = payloadToVerify.getBytes(StandardCharsets.UTF_8);
            byte[] signatureBytes = Base64.getDecoder().decode(request.signature());
            byte[] identityKeyBytes = Base64.getDecoder().decode(senderBundle.getIdentityKey());

            boolean isValid = signatureService.verify(messageBytes, signatureBytes, identityKeyBytes);
            if (!isValid) {
                recordAuditLog(sender, AuditEventType.SIGNATURE_VERIFICATION_FAILED,
                        "Message signature verification failed for messageId: " + request.messageId());
                throw new IllegalArgumentException("Invalid message signature: sender authentication failed");
            }
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            recordAuditLog(sender, AuditEventType.SIGNATURE_VERIFICATION_FAILED,
                    "Malformed message signature: " + ex.getMessage());
            throw new IllegalArgumentException("Invalid signature encoding: " + ex.getMessage());
        }

        // 4. Zero-Knowledge persistence: store only ciphertext and transmission metadata
        MessageEntity messageEntity = new MessageEntity(
                request.messageId(),
                sender,
                recipient,
                request.ciphertext(),
                request.nonce(),
                request.signature(),
                request.sequenceNumber()
        );

        if (request.ephemeralKemCiphertext() != null && !request.ephemeralKemCiphertext().isBlank()) {
            messageEntity.setEphemeralKemCiphertext(request.ephemeralKemCiphertext());
        }
        messageEntity.setStatus(MessageStatus.SENT);

        MessageEntity saved = messageRepository.save(messageEntity);
        recordAuditLog(sender, AuditEventType.MESSAGE_SENT, "Encrypted message sent to " + recipient.getUsername());
        log.info("Message [{}] stored successfully from '{}' to '{}'", saved.getMessageId(), senderUsername, recipient.getUsername());

        return mapToDto(saved);
    }

    /**
     * Retrieves all pending/offline messages queued for the recipient and transitions them to DELIVERED.
     */
    @Transactional
    public List<EncryptedMessageDto> getPendingMessages(String recipientUsername) {
        UserEntity recipient = userRepository.findByUsername(recipientUsername)
                .orElseThrow(() -> new ResourceNotFoundException("User '" + recipientUsername + "' not found"));

        List<MessageEntity> pending = messageRepository.findByRecipientUsernameAndStatusOrderBySentAtAsc(
                recipientUsername, MessageStatus.SENT);

        for (MessageEntity m : pending) {
            m.markDelivered();
        }
        messageRepository.saveAll(pending);

        if (!pending.isEmpty()) {
            recordAuditLog(recipient, AuditEventType.MESSAGE_DELIVERED,
                    "Delivered " + pending.size() + " pending messages to " + recipientUsername);
        }

        return pending.stream().map(this::mapToDto).toList();
    }

    /**
     * Retrieves the encrypted conversation history between two peers.
     */
    @Transactional(readOnly = true)
    public List<EncryptedMessageDto> getConversationHistory(String username, String peerUsername) {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User '" + username + "' not found"));
        UserEntity peer = userRepository.findByUsername(peerUsername)
                .orElseThrow(() -> new ResourceNotFoundException("Peer '" + peerUsername + "' not found"));

        return messageRepository.findConversationBetweenUsers(user.getId(), peer.getId()).stream()
                .map(this::mapToDto)
                .toList();
    }

    /**
     * Acknowledges message delivery or updates read receipts.
     */
    @Transactional
    public EncryptedMessageDto updateMessageStatus(String recipientUsername, String messageId, MessageStatus newStatus) {
        MessageEntity message = messageRepository.findByMessageId(messageId)
                .orElseThrow(() -> new ResourceNotFoundException("Message not found: " + messageId));

        if (!message.getRecipient().getUsername().equals(recipientUsername)) {
            throw new AuthorizationException("Unauthorized to update status of this message");
        }

        if (newStatus == MessageStatus.DELIVERED) {
            message.markDelivered();
        } else if (newStatus == MessageStatus.READ) {
            if (message.getDeliveredAt() == null) {
                message.markDelivered();
            }
            message.markRead();
        }

        MessageEntity saved = messageRepository.save(message);
        return mapToDto(saved);
    }

    public static String buildPayloadString(String messageId, long sequenceNumber, String nonce, String ciphertext) {
        return messageId + ":" + sequenceNumber + ":" + nonce + ":" + ciphertext;
    }

    public EncryptedMessageDto mapToDto(MessageEntity m) {
        return new EncryptedMessageDto(
                m.getId(),
                m.getMessageId(),
                m.getSender().getId(),
                m.getSender().getUsername(),
                m.getRecipient().getId(),
                m.getRecipient().getUsername(),
                m.getCiphertext(),
                m.getNonce(),
                m.getEphemeralKemCiphertext(),
                m.getSignature(),
                m.getSequenceNumber(),
                m.getStatus().name(),
                m.getSentAt(),
                m.getDeliveredAt(),
                m.getReadAt()
        );
    }

    private void recordAuditLog(UserEntity user, AuditEventType eventType, String details) {
        try {
            auditLogRepository.save(new AuditLogEntity(user, eventType, "127.0.0.1", details));
        } catch (Exception e) {
            log.error("Failed to write audit log for event {}: {}", eventType, e.getMessage());
        }
    }
}
