package com.securechat.client.net;

import com.securechat.client.protocol.PqSessionManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class ApiClientTest {

    @Test
    @DisplayName("Should initialize with normalized base URL and set auth token")
    void testApiClientInitialization() {
        ApiClient client = new ApiClient("http://localhost:8080/api/v1/");
        assertNull(client.getAuthToken());

        client.setAuthToken("sample.jwt.token");
        assertEquals("sample.jwt.token", client.getAuthToken());
    }

    @Test
    @DisplayName("Should format public key fingerprint in readable 4-byte hex blocks")
    void testKeyFingerprintFormatting() {
        byte[] sampleKey = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        String b64 = Base64.getEncoder().encodeToString(sampleKey);

        String fp = PqSessionManager.computeKeyFingerprint(b64);
        assertNotNull(fp);
        assertFalse(fp.isEmpty());
        assertTrue(fp.contains(" "));
        assertEquals(8, fp.split(" ").length); // 32-byte SHA-256 in 4-byte groups = 8 groups
    }

    @Test
    @DisplayName("Should construct canonical payload string for ML-DSA signing")
    void testBuildPayloadString() {
        String payload = PqSessionManager.buildPayloadString("uuid-1", 42L, "nonce123", "ciphertext456");
        assertEquals("uuid-1:42:nonce123:ciphertext456", payload);
    }
}
