package com.securechat.common.crypto;

import com.securechat.common.crypto.impl.AesGcmEncryptionService;
import com.securechat.common.exception.CryptoException;
import com.securechat.common.exception.MessageDecryptionException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AesGcmEncryptionServiceTest {

    private final AesGcmEncryptionService encryptionService = new AesGcmEncryptionService();
    private final SecureRandom secureRandom = new SecureRandom();

    private byte[] generateRandomKey() {
        byte[] key = new byte[32]; // 256 bits
        secureRandom.nextBytes(key);
        return key;
    }

    @Test
    @DisplayName("AES-256-GCM: Should encrypt and decrypt plaintext successfully")
    void testEncryptDecryptRoundtrip() {
        byte[] key = generateRandomKey();
        byte[] plaintext = "Confidential chat message payload: Hello Quantum World!".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "header:sender=alice;recipient=bob;seq=1".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = encryptionService.encrypt(plaintext, key, aad);
        assertNotNull(encrypted);
        // Minimum size: 12 bytes IV + plaintext length + 16 bytes Auth Tag
        assertEquals(12 + plaintext.length + 16, encrypted.length);

        byte[] decrypted = encryptionService.decrypt(encrypted, key, aad);
        assertArrayEquals(plaintext, decrypted, "Decrypted text must match original plaintext");
    }

    @Test
    @DisplayName("AES-256-GCM: Must generate fresh nonces for identical plaintexts")
    void testNonceUniqueness() {
        byte[] key = generateRandomKey();
        byte[] plaintext = "Identical Plaintext Message".getBytes(StandardCharsets.UTF_8);

        byte[] enc1 = encryptionService.encrypt(plaintext, key, null);
        byte[] enc2 = encryptionService.encrypt(plaintext, key, null);

        // Different nonces guarantee completely different ciphertexts
        assertFalse(Arrays.equals(enc1, enc2),
                "Encrypting identical plaintext must yield distinct ciphertexts due to fresh nonces");

        // The first 12 bytes (the IVs) must also be different
        byte[] iv1 = Arrays.copyOfRange(enc1, 0, 12);
        byte[] iv2 = Arrays.copyOfRange(enc2, 0, 12);
        assertFalse(Arrays.equals(iv1, iv2), "IVs must be distinct");
    }

    @Test
    @DisplayName("AES-256-GCM: Tampered ciphertext or tag must fail authentication")
    void testTamperResistance() {
        byte[] key = generateRandomKey();
        byte[] plaintext = "Secret Message To Protect".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = encryptionService.encrypt(plaintext, key, null);

        // Corrupt a byte in the ciphertext payload
        byte[] tampered = encrypted.clone();
        tampered[15] ^= 0x01;

        assertThrows(MessageDecryptionException.class, () -> {
            encryptionService.decrypt(tampered, key, null);
        }, "Tampered ciphertext must cause authentication failure");
    }

    @Test
    @DisplayName("AES-256-GCM: Mismatched Authenticated Additional Data (AAD) must fail decryption")
    void testAadIntegrity() {
        byte[] key = generateRandomKey();
        byte[] plaintext = "Message with bound header metadata".getBytes(StandardCharsets.UTF_8);
        byte[] aadOriginal = "sequence=1;timestamp=1000".getBytes(StandardCharsets.UTF_8);
        byte[] aadTampered = "sequence=2;timestamp=1000".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = encryptionService.encrypt(plaintext, key, aadOriginal);

        assertThrows(MessageDecryptionException.class, () -> {
            encryptionService.decrypt(encrypted, key, aadTampered);
        }, "Decryption must fail if AAD does not match what was used during encryption");
    }

    @Test
    @DisplayName("AES-256-GCM: Invalid key lengths must be rejected immediately")
    void testInvalidKeyLengths() {
        byte[] shortKey = new byte[16]; // 128-bit key is rejected (256-bit required)
        byte[] plaintext = "Test".getBytes(StandardCharsets.UTF_8);

        assertThrows(CryptoException.class, () -> {
            encryptionService.encrypt(plaintext, shortKey, null);
        });
    }
}
