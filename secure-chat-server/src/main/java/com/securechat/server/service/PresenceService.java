package com.securechat.server.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service managing real-time online presence and connection tracking
 * for authenticated WebSocket clients.
 */
@Service
public class PresenceService {

    private static final Logger log = LoggerFactory.getLogger(PresenceService.class);

    // Maps username -> active WebSocket session IDs
    private final Map<String, Set<String>> userSessions = new ConcurrentHashMap<>();

    // Maps session ID -> username for fast lookup on disconnect
    private final Map<String, String> sessionToUser = new ConcurrentHashMap<>();

    private final NotificationService notificationService;

    public PresenceService(NotificationService notificationService) {
        this.notificationService = notificationService;
    }

    /**
     * Registers a new active WebSocket session for a user and broadcasts ONLINE status if freshly connected.
     */
    public void registerSession(String username, String sessionId) {
        if (username == null || sessionId == null) {
            return;
        }

        sessionToUser.put(sessionId, username);
        userSessions.compute(username, (user, sessions) -> {
            boolean wasOffline = (sessions == null || sessions.isEmpty());
            if (sessions == null) {
                sessions = ConcurrentHashMap.newKeySet();
            }
            sessions.add(sessionId);

            if (wasOffline) {
                log.info("User '{}' came ONLINE (session: {})", username, sessionId);
                notificationService.broadcastPresence(username, true);
            }
            return sessions;
        });
    }

    /**
     * Unregisters a WebSocket session and broadcasts OFFLINE status if all user sessions are closed.
     */
    public void unregisterSession(String sessionId) {
        if (sessionId == null) {
            return;
        }

        String username = sessionToUser.remove(sessionId);
        if (username == null) {
            return;
        }

        userSessions.computeIfPresent(username, (user, sessions) -> {
            sessions.remove(sessionId);
            if (sessions.isEmpty()) {
                log.info("User '{}' went OFFLINE (all sessions closed)", username);
                notificationService.broadcastPresence(username, false);
                return null; // Removes from userSessions map
            }
            return sessions;
        });
    }

    /**
     * Returns whether a user currently has at least one active WebSocket session.
     */
    public boolean isUserOnline(String username) {
        if (username == null) {
            return false;
        }
        Set<String> sessions = userSessions.get(username);
        return sessions != null && !sessions.isEmpty();
    }

    /**
     * Returns an unmodifiable snapshot of all currently online usernames.
     */
    public Set<String> getOnlineUsers() {
        return Collections.unmodifiableSet(userSessions.keySet());
    }
}
