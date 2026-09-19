package com.securechat.common.crypto;

import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.KeyExchangeService.KemSecret;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MlKemKeyExchangeServiceTest {

    private final MlKemKeyExchangeService kem768 = MlKemKeyExchangeService.mlKem768();
    private final MlKemKeyExchangeService kem1024 = MlKemKeyExchangeService.mlKem1024();

    @Test
    @DisplayName("ML-KEM-768: Should generate keypair with exact NIST FIPS 203 sizes")
    void testMlKem768KeyPairSizes() {
        KemKeyPair keyPair = kem768.generateKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.publicKey());
        assertNotNull(keyPair.privateKey());
        assertEquals("ML-KEM-768", keyPair.parameterSet());

        // NIST FIPS 203 Specification: ML-KEM-768 public key = 1184 bytes, private key = 2400 bytes
        assertEquals(1184, keyPair.publicKey().length, "ML-KEM-768 public key must be exactly 1184 bytes");
        assertEquals(2400, keyPair.privateKey().length, "ML-KEM-768 private key must be exactly 2400 bytes");
    }

    @Test
    @DisplayName("ML-KEM-768: Encapsulation and Decapsulation should establish matching 256-bit shared secrets")
    void testMlKem768Roundtrip() {
        // Bob generates a KEM keypair
        KemKeyPair bobKeyPair = kem768.generateKeyPair();

        // Alice encapsulates a shared secret using Bob's public key
        KemSecret aliceSecret = kem768.encapsulate(bobKeyPair.publicKey());
        assertNotNull(aliceSecret.encapsulationCiphertext());
        assertNotNull(aliceSecret.sharedSecret());

        // NIST FIPS 203: ML-KEM-768 ciphertext = 1088 bytes, shared secret = 32 bytes (256 bits)
        assertEquals(1088, aliceSecret.encapsulationCiphertext().length);
        assertEquals(32, aliceSecret.sharedSecret().length);

        // Bob decapsulates the shared secret using his private key and Alice's ciphertext
        byte[] bobSharedSecret = kem768.decapsulate(bobKeyPair.privateKey(), aliceSecret.encapsulationCiphertext());

        // Both parties must hold the identical 256-bit secret
        assertArrayEquals(aliceSecret.sharedSecret(), bobSharedSecret,
                "Decapsulated shared secret must match encapsulated shared secret");
    }

    @Test
    @DisplayName("ML-KEM-768: Tampered ciphertext must not yield the original shared secret (Implicit Rejection)")
    void testMlKem768TamperResistance() {
        KemKeyPair bobKeyPair = kem768.generateKeyPair();
        KemSecret aliceSecret = kem768.encapsulate(bobKeyPair.publicKey());

        byte[] tamperedCiphertext = aliceSecret.encapsulationCiphertext().clone();
        tamperedCiphertext[0] ^= 0x01; // Flip 1 bit

        byte[] bobSharedSecret = kem768.decapsulate(bobKeyPair.privateKey(), tamperedCiphertext);

        // Per NIST FIPS 203 Fujisaki-Okamoto transform, decapsulation of an invalid ciphertext
        // deterministically generates a pseudo-random value that does NOT match the real secret
        assertFalse(java.util.Arrays.equals(aliceSecret.sharedSecret(), bobSharedSecret),
                "Tampered ciphertext must not produce the authentic shared secret");
    }

    @Test
    @DisplayName("ML-KEM-1024: Should support highest security level with correct NIST sizes")
    void testMlKem1024Roundtrip() {
        KemKeyPair keyPair = kem1024.generateKeyPair();

        // NIST FIPS 203: ML-KEM-1024 public key = 1568 bytes, private key = 3168 bytes
        assertEquals(1568, keyPair.publicKey().length);
        assertEquals(3168, keyPair.privateKey().length);

        KemSecret secret = kem1024.encapsulate(keyPair.publicKey());
        assertEquals(1568, secret.encapsulationCiphertext().length);
        assertEquals(32, secret.sharedSecret().length);

        byte[] recovered = kem1024.decapsulate(keyPair.privateKey(), secret.encapsulationCiphertext());
        assertArrayEquals(secret.sharedSecret(), recovered);
    }
}
