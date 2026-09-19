package com.securechat.server.controller;

import com.securechat.server.entity.UserEntity;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.MessageRepository;
import com.securechat.server.repository.OneTimePrekeyRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
import com.securechat.server.repository.UserRepository;
import com.securechat.server.security.JwtTokenProvider;
import com.securechat.server.security.WebSocketAuthInterceptor;
import com.securechat.server.service.PresenceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PresenceControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private PresenceService presenceService;

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

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private WebSocketAuthInterceptor authInterceptor;

    private UserEntity alice;
    private String aliceToken;

    @BeforeEach
    void setUp() {
        messageRepository.deleteAll();
        prekeyRepository.deleteAll();
        keyBundleRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        alice = userRepository.save(new UserEntity("alice_p", "alice_p@latticechat.internal", "hashP", "Alice P"));
        aliceToken = jwtTokenProvider.generateToken(alice);
    }

    @Test
    @DisplayName("GET /api/v1/presence/online: Should return 401 Unauthorized if unauthenticated")
    void testPresenceUnauthenticated() throws Exception {
        mockMvc.perform(get("/api/v1/presence/online"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /api/v1/presence/online: Should return list of active users")
    void testGetOnlineUsers() throws Exception {
        presenceService.registerSession("alice_p", "sess-test-1");

        mockMvc.perform(get("/api/v1/presence/online")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data[0]").value("alice_p"));

        // Cleanup session
        presenceService.unregisterSession("sess-test-1");
    }

    @Test
    @DisplayName("GET /api/v1/presence/{username}: Should return boolean presence status")
    void testIsUserOnline() throws Exception {
        mockMvc.perform(get("/api/v1/presence/alice_p")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value(false));

        presenceService.registerSession("alice_p", "sess-test-2");

        mockMvc.perform(get("/api/v1/presence/alice_p")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value(true));

        presenceService.unregisterSession("sess-test-2");
    }

    @Test
    @DisplayName("WebSocketAuthInterceptor: Should authenticate STOMP CONNECT frame with valid Bearer token")
    void testWebSocketAuthInterceptor() {
        StompHeaderAccessor accessor = StompHeaderAccessor.create(StompCommand.CONNECT);
        accessor.setNativeHeader("Authorization", "Bearer " + aliceToken);
        accessor.setSessionId("ws-session-001");
        accessor.setLeaveMutable(true);
        Message<byte[]> message = MessageBuilder.createMessage(new byte[0], accessor.getMessageHeaders());

        Message<?> processed = authInterceptor.preSend(message, null);
        StompHeaderAccessor processedAccessor = StompHeaderAccessor.wrap(processed);

        assertNotNull(processedAccessor.getUser());
        assertEquals("alice_p", processedAccessor.getUser().getName());
    }

    @Test
    @DisplayName("WebSocketAuthInterceptor: Should leave user unset when STOMP token is invalid")
    void testWebSocketAuthInterceptorInvalidToken() {
        StompHeaderAccessor accessor = StompHeaderAccessor.create(StompCommand.CONNECT);
        accessor.setNativeHeader("Authorization", "Bearer invalid.jwt.token");
        accessor.setSessionId("ws-session-002");
        accessor.setLeaveMutable(true);
        Message<byte[]> message = MessageBuilder.createMessage(new byte[0], accessor.getMessageHeaders());

        Message<?> processed = authInterceptor.preSend(message, null);
        StompHeaderAccessor processedAccessor = StompHeaderAccessor.wrap(processed);

        assertNull(processedAccessor.getUser());
    }
}
