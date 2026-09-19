package com.securechat.common.crypto;

import com.securechat.common.crypto.impl.AesGcmEncryptionService;
import com.securechat.common.crypto.impl.HkdfKeyDerivationService;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.exception.CryptoException;
import com.securechat.common.exception.MessageDecryptionException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Rigorous Cryptographic Edge-Case, Boundary, and Tamper Verification Suite.
 * Validates security guarantees under adversarial mutations and boundary inputs.
 */
class CryptoEdgeCaseTest {

    private final MlKemKeyExchangeService mlKem = MlKemKeyExchangeService.mlKem768();
    private final MlDsaSignatureService mlDsa = MlDsaSignatureService.mlDsa65();
    private final AesGcmEncryptionService aesGcm = new AesGcmEncryptionService();
    private final HkdfKeyDerivationService hkdf = new HkdfKeyDerivationService();

    // =========================================================================
    // 1. Post-Quantum KEM Edge Cases (FIPS 203)
    // =========================================================================

    @Test
    @DisplayName("ML-KEM-768: Ciphertext bit-flip triggers Fujisaki-Okamoto constant-time implicit rejection")
    void testMlKemCiphertextTamperingImplicitRejection() {
        KeyExchangeService.KemKeyPair keyPair = mlKem.generateKeyPair();
        KeyExchangeService.KemSecret encapsulation = mlKem.encapsulate(keyPair.publicKey());

        byte[] originalSecret = encapsulation.sharedSecret();
        byte[] tamperedCiphertext = encapsulation.encapsulationCiphertext().clone();

        // Mutate multiple byte positions within the 1088-byte ciphertext
        tamperedCiphertext[0] ^= 0x42;
        tamperedCiphertext[100] ^= 0x7F;
        tamperedCiphertext[tamperedCiphertext.length - 1] ^= 0x01;

        // FIPS 203 Fujisaki-Okamoto transform guarantees constant-time decapsulation to a pseudorandom secret
        byte[] rejectedSecret = mlKem.decapsulate(keyPair.privateKey(), tamperedCiphertext);

        assertNotNull(rejectedSecret);
        assertEquals(originalSecret.length, rejectedSecret.length);
        assertFalse(Arrays.equals(originalSecret, rejectedSecret),
                "Decapsulation of mutated ciphertext must produce an orthogonal pseudorandom secret (implicit rejection)");
    }

    @Test
    @DisplayName("ML-KEM-768: Truncated or malformed ciphertext rejects cleanly with CryptoException")
    void testMlKemTruncatedCiphertextRejection() {
        KeyExchangeService.KemKeyPair keyPair = mlKem.generateKeyPair();
        byte[] truncatedCiphertext = new byte[100]; // Expected 1088 bytes for ML-KEM-768

        assertThrows(CryptoException.class, () -> mlKem.decapsulate(keyPair.privateKey(), truncatedCiphertext));
        assertThrows(CryptoException.class, () -> mlKem.decapsulate(keyPair.privateKey(), new byte[0]));
        assertThrows(CryptoException.class, () -> mlKem.decapsulate(keyPair.privateKey(), null));
    }

    // =========================================================================
    // 2. Post-Quantum DSA Edge Cases (FIPS 204)
    // =========================================================================

    @Test
    @DisplayName("ML-DSA-65: Systematic bit-flip signature mutation produces deterministic verification rejection")
    void testMlDsaSingleBitFlipRejection() {
        SignatureService.SignatureKeyPair keyPair = mlDsa.generateKeyPair();
        byte[] message = "Critical Financial Wire Instruction #98234".getBytes(StandardCharsets.UTF_8);
        byte[] signature = mlDsa.sign(message, keyPair.privateKey());

        assertTrue(mlDsa.verify(message, signature, keyPair.publicKey()), "Unmodified signature must verify");

        // Test bit flips across various segments of the 3309-byte signature
        int[] testOffsets = {0, 1, 10, 50, 100, 500, 1000, 2000, 3000, signature.length - 1};
        for (int offset : testOffsets) {
            byte[] mutatedSig = signature.clone();
            mutatedSig[offset] ^= 0x01; // flip least-significant bit

            boolean verified = mlDsa.verify(message, mutatedSig, keyPair.publicKey());
            assertFalse(verified, "Signature with flipped bit at offset " + offset + " must be strictly rejected");
        }
    }

    @Test
    @DisplayName("ML-DSA-65: Tampered message fails verification against valid signature")
    void testMlDsaTamperedMessageRejection() {
        SignatureService.SignatureKeyPair keyPair = mlDsa.generateKeyPair();
        byte[] originalMessage = "Transfer $1,000 to Bob".getBytes(StandardCharsets.UTF_8);
        byte[] tamperedMessage = "Transfer $1,000,000 to Eve".getBytes(StandardCharsets.UTF_8);

        byte[] signature = mlDsa.sign(originalMessage, keyPair.privateKey());

        assertTrue(mlDsa.verify(originalMessage, signature, keyPair.publicKey()));
        assertFalse(mlDsa.verify(tamperedMessage, signature, keyPair.publicKey()),
                "Valid signature must fail when verified against tampered message");
    }

    // =========================================================================
    // 3. AES-256-GCM Boundary & AEAD Edge Cases
    // =========================================================================

    @Test
    @DisplayName("AES-256-GCM: Zero-length plaintext encrypts and decrypts correctly (28 bytes wire overhead)")
    void testAesGcmEmptyPlaintextRoundtrip() {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        byte[] emptyPayload = new byte[0];
        byte[] aad = "metadata-header".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = aesGcm.encrypt(emptyPayload, key, aad);

        assertNotNull(ciphertext);
        // Wire format: 12 bytes IV + 0 bytes encrypted body + 16 bytes GCM tag = 28 bytes
        assertEquals(AesGcmEncryptionService.IV_LENGTH_BYTES + AesGcmEncryptionService.TAG_LENGTH_BYTES, ciphertext.length);

        byte[] decrypted = aesGcm.decrypt(ciphertext, key, aad);
        assertArrayEquals(emptyPayload, decrypted);
    }

    @Test
    @DisplayName("AES-256-GCM: Authenticated tag tampering throws MessageDecryptionException")
    void testAesGcmTagTamperingFails() {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        byte[] plaintext = "Confidential ratcheted message payload".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = aesGcm.encrypt(plaintext, key, null);

        // Mutate the last byte (authentication tag)
        ciphertext[ciphertext.length - 1] ^= 0xFF;

        assertThrows(MessageDecryptionException.class, () -> aesGcm.decrypt(ciphertext, key, null));
    }

    @Test
    @DisplayName("AES-256-GCM: Associated Data (AAD) mismatch causes authentication failure")
    void testAesGcmAssociatedDataMismatchFails() {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        byte[] plaintext = "Ratcheted stream data".getBytes(StandardCharsets.UTF_8);
        byte[] validAad = "sequence=42;sender=alice".getBytes(StandardCharsets.UTF_8);
        byte[] invalidAad = "sequence=43;sender=alice".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = aesGcm.encrypt(plaintext, key, validAad);

        assertThrows(MessageDecryptionException.class, () -> aesGcm.decrypt(ciphertext, key, invalidAad));
    }

    @Test
    @DisplayName("AES-256-GCM: Nonce collision resistance over 1,000 successive encryptions")
    void testAesGcmNonceUniqueness() {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        byte[] plaintext = "Ping".getBytes(StandardCharsets.UTF_8);

        Set<String> ivSet = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            byte[] ciphertext = aesGcm.encrypt(plaintext, key, null);
            byte[] iv = Arrays.copyOfRange(ciphertext, 0, AesGcmEncryptionService.IV_LENGTH_BYTES);
            String ivHex = java.util.HexFormat.of().formatHex(iv);
            boolean added = ivSet.add(ivHex);
            assertTrue(added, "IV collision detected at iteration " + i);
        }
        assertEquals(1000, ivSet.size());
    }

    @Test
    @DisplayName("AES-256-GCM: Invalid key lengths are rejected immediately")
    void testAesGcmInvalidKeyLengths() {
        byte[] plaintext = "Test".getBytes(StandardCharsets.UTF_8);

        assertThrows(CryptoException.class, () -> aesGcm.encrypt(plaintext, new byte[16], null)); // AES-128 rejected
        assertThrows(CryptoException.class, () -> aesGcm.encrypt(plaintext, new byte[24], null)); // AES-192 rejected
        assertThrows(CryptoException.class, () -> aesGcm.encrypt(plaintext, new byte[31], null));
        assertThrows(CryptoException.class, () -> aesGcm.encrypt(plaintext, new byte[33], null));
        assertThrows(CryptoException.class, () -> aesGcm.encrypt(plaintext, null, null));
    }

    // =========================================================================
    // 4. HKDF-SHA256 Derivation Stability & Boundary Inputs
    // =========================================================================

    @Test
    @DisplayName("HKDF-SHA256: Derivation stability with null salt, empty info, and custom output lengths")
    void testHkdfBoundaryInputs() {
        byte[] ikm = "SuperSecretInputKeyingMaterial123!".getBytes(StandardCharsets.UTF_8);

        // Derivation with null salt and empty info
        byte[] key32 = hkdf.deriveKey(ikm, null, new byte[0], 32);
        assertNotNull(key32);
        assertEquals(32, key32.length);

        // Verify deterministic reproducibility
        byte[] key32Repeat = hkdf.deriveKey(ikm, null, new byte[0], 32);
        assertArrayEquals(key32, key32Repeat);

        // Custom output key lengths
        byte[] key16 = hkdf.deriveKey(ikm, "salt".getBytes(StandardCharsets.UTF_8), "info".getBytes(StandardCharsets.UTF_8), 16);
        byte[] key64 = hkdf.deriveKey(ikm, "salt".getBytes(StandardCharsets.UTF_8), "info".getBytes(StandardCharsets.UTF_8), 64);
        assertEquals(16, key16.length);
        assertEquals(64, key64.length);

        // Orthogonality between distinct info contexts
        byte[] keyInfoA = hkdf.deriveKey(ikm, "salt".getBytes(), "contextA".getBytes(), 32);
        byte[] keyInfoB = hkdf.deriveKey(ikm, "salt".getBytes(), "contextB".getBytes(), 32);
        assertFalse(Arrays.equals(keyInfoA, keyInfoB));
    }
}
