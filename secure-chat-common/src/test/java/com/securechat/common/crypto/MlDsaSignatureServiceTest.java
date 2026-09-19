package com.securechat.common.crypto;

import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class MlDsaSignatureServiceTest {

    private final MlDsaSignatureService dsa65 = MlDsaSignatureService.mlDsa65();
    private final MlDsaSignatureService dsa87 = MlDsaSignatureService.mlDsa87();

    @Test
    @DisplayName("ML-DSA-65: Should generate keypair with exact NIST FIPS 204 sizes")
    void testMlDsa65KeyPairSizes() {
        SignatureKeyPair keyPair = dsa65.generateKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.publicKey());
        assertNotNull(keyPair.privateKey());
        assertEquals("ML-DSA-65", keyPair.parameterSet());

        // NIST FIPS 204 Specification: ML-DSA-65 public key = 1952 bytes, private key = 4032 bytes
        assertEquals(1952, keyPair.publicKey().length, "ML-DSA-65 public key must be 1952 bytes");
        assertEquals(4032, keyPair.privateKey().length, "ML-DSA-65 private key must be 4032 bytes");
    }

    @Test
    @DisplayName("ML-DSA-65: Should generate valid signature and verify authentic message")
    void testMlDsa65SignAndVerify() {
        SignatureKeyPair keyPair = dsa65.generateKeyPair();
        byte[] message = "LatticeChat: Post-Quantum Security Protocol".getBytes(StandardCharsets.UTF_8);

        byte[] signature = dsa65.sign(message, keyPair.privateKey());
        assertNotNull(signature);

        // NIST FIPS 204 Specification: ML-DSA-65 signature = 3309 bytes
        assertEquals(3309, signature.length, "ML-DSA-65 signature must be exactly 3309 bytes");

        boolean isValid = dsa65.verify(message, signature, keyPair.publicKey());
        assertTrue(isValid, "Valid signature must verify successfully");
    }

    @Test
    @DisplayName("ML-DSA-65: Should reject tampered message payload")
    void testMlDsa65TamperedMessage() {
        SignatureKeyPair keyPair = dsa65.generateKeyPair();
        byte[] originalMessage = "Transfer $1,000 to Bob".getBytes(StandardCharsets.UTF_8);
        byte[] tamperedMessage = "Transfer $9,999 to Eve".getBytes(StandardCharsets.UTF_8);

        byte[] signature = dsa65.sign(originalMessage, keyPair.privateKey());

        boolean isValid = dsa65.verify(tamperedMessage, signature, keyPair.publicKey());
        assertFalse(isValid, "Signature verification must fail for tampered message");
    }

    @Test
    @DisplayName("ML-DSA-65: Should reject tampered signature bytes")
    void testMlDsa65TamperedSignature() {
        SignatureKeyPair keyPair = dsa65.generateKeyPair();
        byte[] message = "Cryptographic Integrity Check".getBytes(StandardCharsets.UTF_8);

        byte[] signature = dsa65.sign(message, keyPair.privateKey());

        byte[] tamperedSignature = signature.clone();
        tamperedSignature[10] ^= 0x55; // Corrupt signature byte

        boolean isValid = dsa65.verify(message, tamperedSignature, keyPair.publicKey());
        assertFalse(isValid, "Signature verification must fail for corrupted signature bytes");
    }

    @Test
    @DisplayName("ML-DSA-65: Should reject signature when verified against wrong public key")
    void testMlDsa65WrongKey() {
        SignatureKeyPair signerKeyPair = dsa65.generateKeyPair();
        SignatureKeyPair impostorKeyPair = dsa65.generateKeyPair();

        byte[] message = "Authentic Signer Payload".getBytes(StandardCharsets.UTF_8);
        byte[] signature = dsa65.sign(message, signerKeyPair.privateKey());

        boolean isValid = dsa65.verify(message, signature, impostorKeyPair.publicKey());
        assertFalse(isValid, "Verification must fail against an unrelated public key");
    }

    @Test
    @DisplayName("ML-DSA-87: Should support highest security level with correct NIST sizes")
    void testMlDsa87Roundtrip() {
        SignatureKeyPair keyPair = dsa87.generateKeyPair();

        // NIST FIPS 204: ML-DSA-87 public key = 2592 bytes, private key = 4896 bytes, sig = 4627 bytes
        assertEquals(2592, keyPair.publicKey().length);
        assertEquals(4896, keyPair.privateKey().length);

        byte[] message = "ML-DSA-87 Test Payload".getBytes(StandardCharsets.UTF_8);
        byte[] signature = dsa87.sign(message, keyPair.privateKey());
        assertEquals(4627, signature.length);

        assertTrue(dsa87.verify(message, signature, keyPair.publicKey()));
    }
}
