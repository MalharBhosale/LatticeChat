package com.securechat.server.service;

import com.securechat.common.dto.EncryptedMessageDto;
import com.securechat.common.dto.ReceiptNotificationDto;
import com.securechat.common.dto.UserPresenceDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.SimpMessagingTemplate;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NotificationServiceTest {

    private TestMessagingTemplate messagingTemplate;
    private NotificationService notificationService;

    static class TestMessagingTemplate extends SimpMessagingTemplate {
        String lastUser;
        String lastDestination;
        Object lastPayload;

        public TestMessagingTemplate() {
            super(new MessageChannel() {
                @Override
                public boolean send(Message<?> message) {
                    return true;
                }

                @Override
                public boolean send(Message<?> message, long timeout) {
                    return true;
                }
            });
        }

        @Override
        public void convertAndSendToUser(String user, String destination, Object payload) {
            this.lastUser = user;
            this.lastDestination = destination;
            this.lastPayload = payload;
        }

        @Override
        public void convertAndSend(String destination, Object payload) {
            this.lastDestination = destination;
            this.lastPayload = payload;
        }
    }

    @BeforeEach
    void setUp() {
        messagingTemplate = new TestMessagingTemplate();
        notificationService = new NotificationService(messagingTemplate);
    }

    @Test
    @DisplayName("Should send message notification to recipient queue /user/{username}/queue/messages")
    void testNotifyNewMessage() {
        EncryptedMessageDto message = new EncryptedMessageDto(
                1L, "msg-001", 10L, "alice", 20L, "bob",
                "ciphertext", "nonce", null, "sig", 1L, "SENT",
                Instant.now(), null, null
        );

        notificationService.notifyNewMessage("bob", message);

        assertEquals("bob", messagingTemplate.lastUser);
        assertEquals("/queue/messages", messagingTemplate.lastDestination);
        assertEquals(message, messagingTemplate.lastPayload);
    }

    @Test
    @DisplayName("Should send delivery receipt notification to sender queue /user/{username}/queue/receipts")
    void testNotifyReceipt() {
        notificationService.notifyReceipt("alice", "msg-001", "DELIVERED");

        assertEquals("alice", messagingTemplate.lastUser);
        assertEquals("/queue/receipts", messagingTemplate.lastDestination);
        assertNotNull(messagingTemplate.lastPayload);
        assertTrue(messagingTemplate.lastPayload instanceof ReceiptNotificationDto);
        ReceiptNotificationDto receipt = (ReceiptNotificationDto) messagingTemplate.lastPayload;
        assertEquals("msg-001", receipt.messageId());
        assertEquals("DELIVERED", receipt.status());
    }

    @Test
    @DisplayName("Should broadcast presence update to topic /topic/presence")
    void testBroadcastPresence() {
        notificationService.broadcastPresence("alice", true);

        assertEquals("/topic/presence", messagingTemplate.lastDestination);
        assertNotNull(messagingTemplate.lastPayload);
        assertTrue(messagingTemplate.lastPayload instanceof UserPresenceDto);
        UserPresenceDto presence = (UserPresenceDto) messagingTemplate.lastPayload;
        assertEquals("alice", presence.username());
        assertTrue(presence.online());
    }
}

