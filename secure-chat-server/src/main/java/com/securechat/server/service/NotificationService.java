package com.securechat.server.service;

import com.securechat.common.dto.EncryptedMessageDto;
import com.securechat.common.dto.ReceiptNotificationDto;
import com.securechat.common.dto.UserPresenceDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;

/**
 * Service managing real-time WebSocket push notifications to online users
 * via STOMP user destinations and broadcast topics.
 */
@Service
public class NotificationService {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

    private final SimpMessagingTemplate messagingTemplate;

    public NotificationService(SimpMessagingTemplate messagingTemplate) {
        this.messagingTemplate = messagingTemplate;
    }

    /**
     * Pushes a real-time zero-knowledge encrypted message to the recipient's private queue (/user/{username}/queue/messages).
     */
    public void notifyNewMessage(String recipientUsername, EncryptedMessageDto message) {
        log.debug("Pushing new encrypted message [{}] to user '{}' via WebSocket", message.messageId(), recipientUsername);
        messagingTemplate.convertAndSendToUser(recipientUsername, "/queue/messages", message);
    }

    /**
     * Pushes a real-time delivery or read receipt to the sender's private queue (/user/{username}/queue/receipts).
     */
    public void notifyReceipt(String senderUsername, String messageId, String status) {
        log.debug("Pushing receipt [{}: {}] to user '{}' via WebSocket", messageId, status, senderUsername);
        ReceiptNotificationDto receipt = new ReceiptNotificationDto(messageId, status, Instant.now());
        messagingTemplate.convertAndSendToUser(senderUsername, "/queue/receipts", receipt);
    }

    /**
     * Broadcasts a user's presence state change to all subscribers (/topic/presence).
     */
    public void broadcastPresence(String username, boolean online) {
        log.info("Broadcasting presence for user '{}': online={}", username, online);
        UserPresenceDto presence = new UserPresenceDto(username, online, Instant.now());
        messagingTemplate.convertAndSend("/topic/presence", presence);
    }
}
