package com.securechat.server.security;

import com.securechat.server.entity.UserEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenProviderTest {

    private JwtTokenProvider tokenProvider;
    private final String secret = "v9y$B&E)H@McQfTjWnZr4u7x!A%D*F-JaNdRgUkXp2s5v8y/B?E(H+MbQeShVmYq";
    private final long expirationMs = 3600000; // 1 hour

    @BeforeEach
    void setUp() {
        tokenProvider = new JwtTokenProvider(secret, expirationMs);
    }

    @Test
    @DisplayName("Should generate valid JWT token with user claims")
    void testGenerateAndValidateToken() {
        UserEntity user = new UserEntity("alice", "alice@latticechat.internal", "hash", "Alice");
        user.setId(42L);

        String token = tokenProvider.generateToken(user);
        assertNotNull(token);
        assertTrue(tokenProvider.validateToken(token));

        assertEquals("alice", tokenProvider.getUsernameFromToken(token));
        assertEquals(42L, tokenProvider.getUserIdFromToken(token));

        Authentication auth = tokenProvider.getAuthentication(token);
        assertNotNull(auth);
        assertEquals("alice", auth.getName());
        assertTrue(auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
    }

    @Test
    @DisplayName("Should reject tampered JWT token")
    void testTamperedTokenRejected() {
        UserEntity user = new UserEntity("bob", "bob@latticechat.internal", "hash", "Bob");
        user.setId(10L);

        String token = tokenProvider.generateToken(user);
        String tamperedToken = token.substring(0, token.length() - 5) + "abcde";

        assertFalse(tokenProvider.validateToken(tamperedToken));
    }

    @Test
    @DisplayName("Should reject expired JWT token")
    void testExpiredTokenRejected() throws InterruptedException {
        // Create a provider with 1 millisecond expiration
        JwtTokenProvider shortLivedProvider = new JwtTokenProvider(secret, 1);
        UserEntity user = new UserEntity("charlie", "charlie@latticechat.internal", "hash", "Charlie");
        user.setId(99L);

        String token = shortLivedProvider.generateToken(user);
        Thread.sleep(50); // Ensure token expires

        assertFalse(shortLivedProvider.validateToken(token));
    }

    @Test
    @DisplayName("Should reject token signed with different key")
    void testInvalidSecretRejected() {
        String otherSecret = "DifferentSecretKeyForTestingPurposes12345678901234567890";
        JwtTokenProvider otherProvider = new JwtTokenProvider(otherSecret, expirationMs);

        UserEntity user = new UserEntity("dave", "dave@latticechat.internal", "hash", "Dave");
        user.setId(1L);

        String tokenFromOther = otherProvider.generateToken(user);

        assertFalse(tokenProvider.validateToken(tokenFromOther));
    }
}
