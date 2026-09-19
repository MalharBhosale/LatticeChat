package com.securechat.common.crypto;

import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.KeyExchangeService.KemSecret;
import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.AesGcmEncryptionService;
import com.securechat.common.crypto.impl.HkdfKeyDerivationService;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.exception.MessageDecryptionException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive integration test simulating the entire LatticeChat Post-Quantum Cryptographic Protocol:
 *
 * 1. Identity & Prekey generation (ML-DSA-65 + ML-KEM-768)
 * 2. Authenticated Prekey Signing & Verification
 * 3. Quantum-resistant Key Encapsulation (ML-KEM)
 * 4. Session Key Derivation (HKDF-SHA256)
 * 5. Authenticated Symmetric Message Encryption (AES-256-GCM)
 * 6. Message Digital Signature & Verification
 * 7. Decapsulation, Derivation, and Decryption
 * 8. Adversarial Tamper Detection
 */
class PostQuantumCryptoEndToEndTest {

    private final MlKemKeyExchangeService kemService = MlKemKeyExchangeService.mlKem768();
    private final MlDsaSignatureService signatureService = MlDsaSignatureService.mlDsa65();
    private final HkdfKeyDerivationService hkdfService = new HkdfKeyDerivationService();
    private final AesGcmEncryptionService encryptionService = new AesGcmEncryptionService();

    @Test
    @DisplayName("End-to-End Post-Quantum Secure Message Exchange Protocol Simulation")
    void testFullProtocolFlow() {
        // ====================================================================
        // STEP 1: Bob generates his Post-Quantum keys (Identity + Prekey)
        // ====================================================================
        SignatureKeyPair bobIdentityKeyPair = signatureService.generateKeyPair();
        KemKeyPair bobPrekeyPair = kemService.generateKeyPair();

        // Bob signs his ML-KEM prekey with his ML-DSA identity key to prevent MitM key substitution
        byte[] bobPrekeySignature = signatureService.sign(bobPrekeyPair.publicKey(), bobIdentityKeyPair.privateKey());

        // ====================================================================
        // STEP 2: Alice discovers Bob's public bundle and verifies authenticity
        // ====================================================================
        boolean isBobPrekeyAuthentic = signatureService.verify(
                bobPrekeyPair.publicKey(),
                bobPrekeySignature,
                bobIdentityKeyPair.publicKey()
        );
        assertTrue(isBobPrekeyAuthentic, "Alice must successfully verify Bob's signed prekey");

        // Alice generates her own identity key for message signing
        SignatureKeyPair aliceIdentityKeyPair = signatureService.generateKeyPair();

        // ====================================================================
        // STEP 3: Alice encapsulates a Post-Quantum shared secret for Bob
        // ====================================================================
        KemSecret aliceKemSecret = kemService.encapsulate(bobPrekeyPair.publicKey());
        byte[] encapsulationCiphertext = aliceKemSecret.encapsulationCiphertext();
        byte[] rawSharedSecretAlice = aliceKemSecret.sharedSecret();

        // ====================================================================
        // STEP 4: Alice derives a 256-bit AES session key using HKDF-SHA256
        // ====================================================================
        byte[] hkdfSalt = "LatticeChat:SessionSalt:v1".getBytes(StandardCharsets.UTF_8);
        byte[] hkdfInfo = "LatticeChat:AES-256-GCM:MessageKey".getBytes(StandardCharsets.UTF_8);

        byte[] aliceSessionKey = hkdfService.deriveKey(rawSharedSecretAlice, hkdfSalt, hkdfInfo, 32);
        assertEquals(32, aliceSessionKey.length, "Session key must be 256 bits (32 bytes)");

        // ====================================================================
        // STEP 5: Alice encrypts her confidential message with AES-256-GCM
        // ====================================================================
        String secretMessageText = "Meeting at 14:00 UTC. The quantum computer has arrived.";
        byte[] plaintext = secretMessageText.getBytes(StandardCharsets.UTF_8);
        byte[] authenticatedHeader = "sender=alice;recipient=bob;version=1".getBytes(StandardCharsets.UTF_8);

        byte[] aesEncryptedMessage = encryptionService.encrypt(plaintext, aliceSessionKey, authenticatedHeader);

        // Alice signs the encrypted ciphertext with her ML-DSA-65 identity key
        byte[] aliceMessageSignature = signatureService.sign(aesEncryptedMessage, aliceIdentityKeyPair.privateKey());

        // ====================================================================
        // STEP 6: Bob receives the packet and verifies Alice's signature
        // ====================================================================
        boolean isMessageSignatureValid = signatureService.verify(
                aesEncryptedMessage,
                aliceMessageSignature,
                aliceIdentityKeyPair.publicKey()
        );
        assertTrue(isMessageSignatureValid, "Bob must verify Alice's digital signature on the ciphertext");

        // ====================================================================
        // STEP 7: Bob decapsulates the shared secret using his ML-KEM private key
        // ====================================================================
        byte[] rawSharedSecretBob = kemService.decapsulate(bobPrekeyPair.privateKey(), encapsulationCiphertext);
        assertArrayEquals(rawSharedSecretAlice, rawSharedSecretBob,
                "Bob's decapsulated secret must match Alice's encapsulated secret");

        // Bob derives the identical 256-bit AES session key via HKDF
        byte[] bobSessionKey = hkdfService.deriveKey(rawSharedSecretBob, hkdfSalt, hkdfInfo, 32);
        assertArrayEquals(aliceSessionKey, bobSessionKey, "Derived session keys must be identical");

        // ====================================================================
        // STEP 8: Bob decrypts the message payload
        // ====================================================================
        byte[] decryptedPlaintext = encryptionService.decrypt(aesEncryptedMessage, bobSessionKey, authenticatedHeader);
        String recoveredMessageText = new String(decryptedPlaintext, StandardCharsets.UTF_8);

        assertEquals(secretMessageText, recoveredMessageText,
                "Decrypted message must match original plaintext exactly");

        // ====================================================================
        // STEP 9: Adversarial Tamper Simulation (Eve alters the ciphertext)
        // ====================================================================
        byte[] tamperedCiphertext = aesEncryptedMessage.clone();
        tamperedCiphertext[16] ^= 0x42; // Eve flips bits in transit

        // A) Digital signature fails immediately
        boolean signatureAfterTampering = signatureService.verify(
                tamperedCiphertext,
                aliceMessageSignature,
                aliceIdentityKeyPair.publicKey()
        );
        assertFalse(signatureAfterTampering, "Tampered ciphertext must fail signature verification");

        // B) Authenticated decryption fails cryptographically (AEAD auth tag mismatch)
        assertThrows(MessageDecryptionException.class, () -> {
            encryptionService.decrypt(tamperedCiphertext, bobSessionKey, authenticatedHeader);
        }, "Tampered ciphertext must fail AES-GCM authentication tag verification");
    }
}
