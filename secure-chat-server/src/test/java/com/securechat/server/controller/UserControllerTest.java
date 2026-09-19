package com.securechat.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.MessageRepository;
import com.securechat.server.repository.OneTimePrekeyRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
import com.securechat.server.repository.UserRepository;
import com.securechat.server.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private UserKeyBundleRepository keyBundleRepository;

    @Autowired
    private MessageRepository messageRepository;

    @Autowired
    private OneTimePrekeyRepository prekeyRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private UserEntity userAlice;
    private UserEntity userBob;
    private String aliceToken;

    @BeforeEach
    void setUp() {
        messageRepository.deleteAll();
        prekeyRepository.deleteAll();
        keyBundleRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        userAlice = userRepository.save(new UserEntity("alice_dir", "alice_dir@latticechat.internal", "hashA", "Alice Dir"));
        userBob = userRepository.save(new UserEntity("bob_dir", "bob_dir@latticechat.internal", "hashB", "Bob Dir"));

        aliceToken = jwtTokenProvider.generateToken(userAlice);
    }

    @Test
    @DisplayName("GET /api/v1/users/me: Should return 401 Unauthorized when token is missing")
    void testMeUnauthenticated() throws Exception {
        mockMvc.perform(get("/api/v1/users/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /api/v1/users/me: Should return user profile when Bearer token is provided")
    void testMeAuthenticated() throws Exception {
        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.username").value("alice_dir"))
                .andExpect(jsonPath("$.data.email").value("alice_dir@latticechat.internal"));
    }

    @Test
    @DisplayName("GET /api/v1/users/search: Should search user directory")
    void testSearchUsers() throws Exception {
        mockMvc.perform(get("/api/v1/users/search")
                        .param("query", "bob")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data[0].username").value("bob_dir"));
    }

    @Test
    @DisplayName("GET /api/v1/users/{username}: Should retrieve user by username")
    void testGetUserByUsername() throws Exception {
        mockMvc.perform(get("/api/v1/users/bob_dir")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.username").value("bob_dir"));
    }
}
