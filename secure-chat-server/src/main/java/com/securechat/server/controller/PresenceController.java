package com.securechat.server.controller;

import com.securechat.common.dto.ApiResponse;
import com.securechat.server.service.PresenceService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

/**
 * REST controller for querying real-time online presence.
 * All endpoints require valid JWT Bearer authentication.
 */
@RestController
@RequestMapping("/api/v1/presence")
public class PresenceController {

    private final PresenceService presenceService;

    public PresenceController(PresenceService presenceService) {
        this.presenceService = presenceService;
    }

    /**
     * Retrieves all currently online usernames.
     */
    @GetMapping("/online")
    public ResponseEntity<ApiResponse<Set<String>>> getOnlineUsers() {
        Set<String> onlineUsers = presenceService.getOnlineUsers();
        return ResponseEntity.ok(ApiResponse.ok("Online users retrieved", onlineUsers));
    }

    /**
     * Checks if a specific user is currently online.
     */
    @GetMapping("/{username}")
    public ResponseEntity<ApiResponse<Boolean>> isUserOnline(@PathVariable("username") String username) {
        boolean online = presenceService.isUserOnline(username);
        return ResponseEntity.ok(ApiResponse.ok("User presence retrieved", online));
    }
}
