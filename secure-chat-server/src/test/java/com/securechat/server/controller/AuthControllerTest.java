package com.securechat.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securechat.common.dto.AuthRequest;
import com.securechat.common.dto.RegisterRequest;
import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.AuditLogEntity;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.MessageRepository;
import com.securechat.server.repository.OneTimePrekeyRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
import com.securechat.server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerTest {

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
        private ObjectMapper objectMapper;

        @BeforeEach
        void setUp() {
                messageRepository.deleteAll();
                prekeyRepository.deleteAll();
                keyBundleRepository.deleteAll();
                auditLogRepository.deleteAll();
                userRepository.deleteAll();
        }

        @Test
        @DisplayName("POST /api/v1/auth/register: Should register new user and return JWT token")
        void testRegisterSuccess() throws Exception {
                RegisterRequest request = new RegisterRequest(
                                "alice_test",
                                "Password123!",
                                "alice_test@latticechat.internal",
                                "MOCK_KEM_KEY",
                                "MOCK_DSA_KEY");

                mockMvc.perform(post("/api/v1/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.success").value(true))
                                .andExpect(jsonPath("$.data.token").isNotEmpty())
                                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                                .andExpect(jsonPath("$.data.user.username").value("alice_test"))
                                .andExpect(jsonPath("$.data.user.email").value("alice_test@latticechat.internal"));

                assertTrue(userRepository.existsByUsername("alice_test"));

                List<AuditLogEntity> logs = auditLogRepository
                                .findByEventTypeOrderByCreatedAtDesc(AuditEventType.USER_REGISTER);
                assertFalse(logs.isEmpty());
        }

        @Test
        @DisplayName("POST /api/v1/auth/register: Should reject duplicate username")
        void testRegisterDuplicateUsername() throws Exception {
                RegisterRequest request = new RegisterRequest(
                                "bob_dup",
                                "Password123!",
                                "bob1@latticechat.internal",
                                null,
                                null);

                mockMvc.perform(post("/api/v1/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isCreated());

                RegisterRequest duplicate = new RegisterRequest(
                                "bob_dup",
                                "Password123!",
                                "bob2@latticechat.internal",
                                null,
                                null);

                mockMvc.perform(post("/api/v1/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(duplicate)))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.success").value(false))
                                .andExpect(jsonPath("$.message").value("Username 'bob_dup' is already taken"));
        }

        @Test
        @DisplayName("POST /api/v1/auth/login: Should authenticate valid credentials and issue JWT")
        void testLoginSuccess() throws Exception {
                // Register user first
                RegisterRequest reg = new RegisterRequest("charlie_login", "StrongPass123!",
                                "charlie@latticechat.internal", null, null);
                mockMvc.perform(post("/api/v1/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(reg)));

                // Attempt login
                AuthRequest loginRequest = new AuthRequest("charlie_login", "StrongPass123!");

                mockMvc.perform(post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.success").value(true))
                                .andExpect(jsonPath("$.data.token").isNotEmpty())
                                .andExpect(jsonPath("$.data.user.username").value("charlie_login"));

                List<AuditLogEntity> loginLogs = auditLogRepository
                                .findByEventTypeOrderByCreatedAtDesc(AuditEventType.USER_LOGIN);
                assertFalse(loginLogs.isEmpty());
        }

        @Test
        @DisplayName("POST /api/v1/auth/login: Should reject invalid password with 401 Unauthorized")
        void testLoginInvalidPassword() throws Exception {
                RegisterRequest reg = new RegisterRequest("dave_auth", "CorrectPass123!", "dave@latticechat.internal",
                                null, null);
                mockMvc.perform(post("/api/v1/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(reg)));

                AuthRequest badLogin = new AuthRequest("dave_auth", "WrongPass123!");

                mockMvc.perform(post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(badLogin)))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.success").value(false))
                                .andExpect(jsonPath("$.message").value("Invalid username or password"));

                List<AuditLogEntity> failedLogs = auditLogRepository
                                .findByEventTypeOrderByCreatedAtDesc(AuditEventType.LOGIN_FAILED);
                assertFalse(failedLogs.isEmpty());
        }
}
