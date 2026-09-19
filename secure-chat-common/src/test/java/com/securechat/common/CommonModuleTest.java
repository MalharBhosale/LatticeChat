package com.securechat.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.securechat.common.dto.ApiResponse;
import com.securechat.common.dto.UserDto;
import com.securechat.common.exception.CryptoException;
import com.securechat.common.exception.MessageDecryptionException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class CommonModuleTest {

    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    @DisplayName("Verify ApiResponse JSON serialization and deserialization")
    void testApiResponseSerialization() throws Exception {
        UserDto user = new UserDto(1L, "alice", "alice@example.com", true, Instant.now());
        ApiResponse<UserDto> response = ApiResponse.ok("User fetched", user);

        String json = objectMapper.writeValueAsString(response);
        assertNotNull(json);
        assertTrue(json.contains("alice"));

        ApiResponse<?> deserialized = objectMapper.readValue(json, ApiResponse.class);
        assertTrue(deserialized.success());
        assertEquals("User fetched", deserialized.message());
    }

    @Test
    @DisplayName("Verify exception inheritance hierarchy")
    void testExceptionHierarchy() {
        MessageDecryptionException exception = new MessageDecryptionException("Decryption tag mismatch");
        assertInstanceOf(CryptoException.class, exception);
        assertEquals("Decryption tag mismatch", exception.getMessage());
    }
}
