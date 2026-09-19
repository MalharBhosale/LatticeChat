package com.securechat.server.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securechat.common.dto.ApiResponse;
import com.securechat.common.dto.AuthRequest;
import com.securechat.common.dto.DeliveryReceiptRequest;
import com.securechat.common.dto.RegisterRequest;
import com.securechat.common.dto.SendMessageRequest;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.exception.GlobalExceptionHandler;
import com.securechat.server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Enterprise-grade Security Hardening Integration Tests.
 * Validates OWASP Top 10 defenses:
 * 1. HTTP Security Headers (CSP, Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
 * 2. Jakarta Bean Validation on DTO input parameters.
 * 3. Rate limiting and IP throttling on sensitive authentication endpoints.
 * 4. Exception sanitization preventing internal stack trace leaks.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class SecurityHardeningTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private RateLimitingFilter rateLimitingFilter;

    private String userToken;

    @BeforeEach
    void setUp() {
        rateLimitingFilter.reset();
        UserEntity user = userRepository.findByUsername("hardening_user")
                .orElseGet(() -> userRepository.save(new UserEntity("hardening_user", "hardening@latticechat.internal", "hash1234", "Hardening User")));
        userToken = jwtTokenProvider.generateToken(user);
    }

    @Test
    @DisplayName("OWASP A05: HTTP Security Headers are present on responses")
    void testSecurityHeadersPresent() throws Exception {
        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'self'")))
                .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"))
                .andExpect(header().string("Permissions-Policy", containsString("camera=()")));
    }

    @Test
    @DisplayName("OWASP A03: Input Validation rejects blank or undersized registration username")
    void testRegisterValidationInvalidUsername() throws Exception {
        RegisterRequest invalid = new RegisterRequest(
                "ab", // Under 3 chars
                "ValidPassword123!",
                "valid@latticechat.internal",
                null,
                null
        );

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalid)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message", containsString("Validation failed")))
                .andExpect(jsonPath("$.message", containsString("username")));
    }

    @Test
    @DisplayName("OWASP A03: Input Validation rejects illegal characters in registration username")
    void testRegisterValidationIllegalCharsInUsername() throws Exception {
        RegisterRequest invalid = new RegisterRequest(
                "user<script>", // XSS / injection probe
                "ValidPassword123!",
                "valid@latticechat.internal",
                null,
                null
        );

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalid)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message", containsString("Validation failed")));
    }

    @Test
    @DisplayName("OWASP A03: Input Validation rejects weak / undersized password")
    void testRegisterValidationWeakPassword() throws Exception {
        RegisterRequest invalid = new RegisterRequest(
                "valid_user",
                "short", // Less than 8 chars
                "valid@latticechat.internal",
                null,
                null
        );

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalid)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message", containsString("Validation failed")))
                .andExpect(jsonPath("$.message", containsString("password")));
    }

    @Test
    @DisplayName("OWASP A03: Input Validation rejects invalid email format")
    void testRegisterValidationInvalidEmail() throws Exception {
        RegisterRequest invalid = new RegisterRequest(
                "valid_user",
                "ValidPassword123!",
                "not-an-email",
                null,
                null
        );

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalid)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message", containsString("Validation failed")))
                .andExpect(jsonPath("$.message", containsString("email")));
    }

    @Test
    @DisplayName("OWASP A03: Input Validation rejects blank login fields")
    void testLoginValidationBlankFields() throws Exception {
        AuthRequest blank = new AuthRequest("", "");

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(blank)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message", containsString("Validation failed")));
    }

    @Test
    @DisplayName("OWASP A03: Input Validation rejects invalid message transmission fields")
    void testSendMessageValidationBlankFields() throws Exception {
        SendMessageRequest blank = new SendMessageRequest(
                "", // Blank recipient
                "", // Blank msg ID
                "", // Blank ciphertext
                "", // Blank nonce
                null,
                "", // Blank signature
                -5L // Invalid negative sequence number
        );

        mockMvc.perform(post("/api/v1/messages")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(blank)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message", containsString("Validation failed")));
    }

    @Test
    @DisplayName("OWASP A03: Input Validation rejects invalid delivery receipt status")
    void testDeliveryReceiptInvalidStatus() throws Exception {
        DeliveryReceiptRequest invalid = new DeliveryReceiptRequest("INVALID_CORRUPTED_STATUS");

        mockMvc.perform(put("/api/v1/messages/msg-999/status")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalid)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message", containsString("Validation failed")));
    }

    @Test
    @DisplayName("OWASP A07: Rate Limiting throttles authentication requests after 15 attempts")
    void testAuthRateLimitingExceeded() throws Exception {
        AuthRequest loginRequest = new AuthRequest("rate_limit_user", "WrongPassword123!");

        // Send 15 requests (within allowed limit)
        for (int i = 0; i < 15; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .header("X-Forwarded-For", "192.168.10.50")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginRequest)))
                    .andExpect(status().isUnauthorized());
        }

        // 16th request must be throttled with HTTP 429
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("X-Forwarded-For", "192.168.10.50")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message", containsString("Rate limit exceeded")));
    }

    @Test
    @DisplayName("OWASP A05: Global Exception Handler sanitizes internal 500 errors with correlation reference")
    void testInternalErrorSanitization() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        RuntimeException sensitiveException = new RuntimeException("SQL syntax error in SELECT * FROM secret_table WHERE root_password='raw'");

        ResponseEntity<ApiResponse<Void>> response = handler.handleGenericException(sensitiveException);

        assertEquals(500, response.getStatusCode().value());
        assertFalse(response.getBody().success());
        assertTrue(response.getBody().message().startsWith("An unexpected internal error occurred. Error reference: "));
        assertFalse(response.getBody().message().contains("secret_table"));
        assertFalse(response.getBody().message().contains("root_password"));
    }
}
