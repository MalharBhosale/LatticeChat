package com.securechat.common.crypto;

import com.securechat.common.crypto.impl.HkdfKeyDerivationService;
import com.securechat.common.exception.CryptoException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class HkdfKeyDerivationServiceTest {

    private final HkdfKeyDerivationService hkdf = new HkdfKeyDerivationService();

    @Test
    @DisplayName("HKDF-SHA256: Should derive 256-bit symmetric key deterministically")
    void testDeriveKeyDeterministic() {
        byte[] ikm = "PostQuantumSharedSecretFromMLKEM768!".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "RandomSaltBytes1234567890123456".getBytes(StandardCharsets.UTF_8);
        byte[] info = "LatticeChat:SessionKey:v1".getBytes(StandardCharsets.UTF_8);

        byte[] key1 = hkdf.deriveKey(ikm, salt, info, 32);
        byte[] key2 = hkdf.deriveKey(ikm, salt, info, 32);

        assertNotNull(key1);
        assertEquals(32, key1.length, "Derived key must be exactly 32 bytes for AES-256");
        assertArrayEquals(key1, key2, "HKDF must be deterministic given identical inputs");
    }

    @Test
    @DisplayName("HKDF-SHA256: Domain separation info must yield independent keys")
    void testDomainSeparation() {
        byte[] ikm = "SharedSecret32BytesMasterSecret!".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "SaltValue1234567890".getBytes(StandardCharsets.UTF_8);

        byte[] encryptionKey = hkdf.deriveKey(ikm, salt, "LatticeChat:EncryptionKey".getBytes(StandardCharsets.UTF_8), 32);
        byte[] authenticationKey = hkdf.deriveKey(ikm, salt, "LatticeChat:AuthKey".getBytes(StandardCharsets.UTF_8), 32);

        assertFalse(Arrays.equals(encryptionKey, authenticationKey),
                "Different info strings must yield cryptographically independent keys");
    }

    @Test
    @DisplayName("HKDF-SHA256: Null salt should be accepted and use default zero-salt")
    void testNullSalt() {
        byte[] ikm = "SharedSecretIKMBytes".getBytes(StandardCharsets.UTF_8);
        byte[] info = "ContextInfo".getBytes(StandardCharsets.UTF_8);

        byte[] key = hkdf.deriveKey(ikm, null, info, 32);
        assertNotNull(key);
        assertEquals(32, key.length);
    }

    @Test
    @DisplayName("HKDF-SHA256: Invalid output lengths or null IKM must be rejected")
    void testInvalidParameters() {
        byte[] ikm = "ValidIKM".getBytes(StandardCharsets.UTF_8);

        assertThrows(CryptoException.class, () -> hkdf.deriveKey(null, null, null, 32));
        assertThrows(CryptoException.class, () -> hkdf.deriveKey(new byte[0], null, null, 32));
        assertThrows(CryptoException.class, () -> hkdf.deriveKey(ikm, null, null, 0));
        assertThrows(CryptoException.class, () -> hkdf.deriveKey(ikm, null, null, 10000));
    }
}
