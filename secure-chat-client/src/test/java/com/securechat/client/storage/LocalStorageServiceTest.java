package com.securechat.client.storage;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LocalStorageServiceTest {

    private LocalStorageService storage;

    @BeforeEach
    void setUp() throws Exception {
        storage = LocalStorageService.inMemory();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (storage != null) {
            storage.close();
        }
    }

    @Test
    @DisplayName("Should save and retrieve established peer sessions")
    void testPeerSessionLifecycle() throws Exception {
        assertFalse(storage.hasSession("bob"));
        assertTrue(storage.getSessionKey("bob").isEmpty());

        storage.saveSession("bob", "sessionKeyBase64Sample", "peerIdentityKeyBase64Sample");
        assertTrue(storage.hasSession("bob"));
        assertEquals("sessionKeyBase64Sample", storage.getSessionKey("bob").orElseThrow());
        assertEquals("peerIdentityKeyBase64Sample", storage.getPeerIdentityKey("bob").orElseThrow());
    }

    @Test
    @DisplayName("Should save, query, and update status of local messages")
    void testLocalMessagePersistence() throws Exception {
        LocalMessage msg1 = new LocalMessage(
                null,
                "msg-001",
                "bob",
                "OUTGOING",
                "Hello Bob!",
                "SENT",
                1L,
                Instant.now().minusSeconds(10)
        );

        LocalMessage msg2 = new LocalMessage(
                null,
                "msg-002",
                "bob",
                "INCOMING",
                "Hi Alice!",
                "DELIVERED",
                2L,
                Instant.now()
        );

        storage.saveMessage(msg1);
        storage.saveMessage(msg2);

        List<LocalMessage> messages = storage.getMessagesForPeer("bob");
        assertEquals(2, messages.size());
        assertEquals("msg-001", messages.get(0).messageId());
        assertEquals("Hello Bob!", messages.get(0).plaintext());
        assertEquals("SENT", messages.get(0).status());
        assertEquals("msg-002", messages.get(1).messageId());
        assertEquals("Hi Alice!", messages.get(1).plaintext());

        // Update status of msg-001
        storage.updateMessageStatus("msg-001", "READ");
        messages = storage.getMessagesForPeer("bob");
        assertEquals("READ", messages.get(0).status());

        // Recent peers
        List<String> peers = storage.getRecentPeers();
        assertEquals(1, peers.size());
        assertEquals("bob", peers.get(0));
    }
}
