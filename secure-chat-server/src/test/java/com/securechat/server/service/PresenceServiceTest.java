package com.securechat.server.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PresenceServiceTest {

    private TestNotificationService notificationService;
    private PresenceService presenceService;

    static class TestNotificationService extends NotificationService {
        final List<String> broadcasts = new ArrayList<>();

        public TestNotificationService() {
            super(null);
        }

        @Override
        public void broadcastPresence(String username, boolean online) {
            broadcasts.add(username + ":" + online);
        }
    }

    @BeforeEach
    void setUp() {
        notificationService = new TestNotificationService();
        presenceService = new PresenceService(notificationService);
    }

    @Test
    @DisplayName("Should track user online on connect and offline on disconnect")
    void testSingleSessionConnectAndDisconnect() {
        assertFalse(presenceService.isUserOnline("alice"));

        presenceService.registerSession("alice", "sess-01");
        assertTrue(presenceService.isUserOnline("alice"));
        assertTrue(notificationService.broadcasts.contains("alice:true"));

        presenceService.unregisterSession("sess-01");
        assertFalse(presenceService.isUserOnline("alice"));
        assertTrue(notificationService.broadcasts.contains("alice:false"));
    }

    @Test
    @DisplayName("Should maintain online status when multiple sessions exist until last session closes")
    void testMultiSessionConnect() {
        presenceService.registerSession("bob", "sess-bob-1");
        presenceService.registerSession("bob", "sess-bob-2");

        assertTrue(presenceService.isUserOnline("bob"));

        // Close first session: user should still be online
        presenceService.unregisterSession("sess-bob-1");
        assertTrue(presenceService.isUserOnline("bob"));

        // Close second session: user is now offline
        presenceService.unregisterSession("sess-bob-2");
        assertFalse(presenceService.isUserOnline("bob"));
    }

    @Test
    @DisplayName("Should return accurate snapshot of all online users")
    void testGetOnlineUsers() {
        presenceService.registerSession("alice", "s1");
        presenceService.registerSession("bob", "s2");
        presenceService.registerSession("charlie", "s3");

        Set<String> online = presenceService.getOnlineUsers();
        assertEquals(3, online.size());
        assertTrue(online.containsAll(Set.of("alice", "bob", "charlie")));

        presenceService.unregisterSession("s2");
        online = presenceService.getOnlineUsers();
        assertEquals(2, online.size());
        assertFalse(online.contains("bob"));
    }
}

