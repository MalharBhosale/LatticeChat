package com.securechat.client.crypto;

import com.securechat.common.crypto.SignatureService;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ClientKeystoreRotationTest {

    private final SignatureService dsaService = new MlDsaSignatureService();

    @Test
    @DisplayName("Rotating signed prekey should produce fresh KEM key authentically signed by permanent identity key")
    void testRotateSignedPrekey() {
        ClientKeystore keystore = ClientKeystore.generateNew(5);
        byte[] originalPrekeyPub = keystore.getSignedPrekey().publicKey().clone();
        byte[] originalSig = keystore.getSignedPrekeySignature().clone();

        // Rotate signed prekey
        var newPrekey = keystore.rotateSignedPrekey();

        assertNotNull(newPrekey);
        assertFalse(java.util.Arrays.equals(originalPrekeyPub, newPrekey.publicKey()));
        assertFalse(java.util.Arrays.equals(originalSig, keystore.getSignedPrekeySignature()));

        // Cryptographically verify new prekey signature against permanent identity key
        boolean isValid = dsaService.verify(
                newPrekey.publicKey(),
                keystore.getSignedPrekeySignature(),
                keystore.getIdentityKey().publicKey()
        );
        assertTrue(isValid, "New signed prekey must be validly signed by permanent ML-DSA-65 identity key");
    }

    @Test
    @DisplayName("Keystore should persist rotated keys to disk and load back correctly")
    void testKeystorePersistenceAfterRotation(@TempDir Path tempDir) throws Exception {
        File keystoreFile = tempDir.resolve("test_rotated.keystore").toFile();
        char[] password = "StrongMasterPassword123!".toCharArray();

        ClientKeystore original = ClientKeystore.generateNew(3);
        var rotatedSpk = original.rotateSignedPrekey();

        original.saveToFile(keystoreFile, password);

        // Load back from disk
        ClientKeystore loaded = ClientKeystore.loadFromFile(keystoreFile, password);

        assertArrayEquals(original.getIdentityKey().publicKey(), loaded.getIdentityKey().publicKey());
        assertArrayEquals(rotatedSpk.publicKey(), loaded.getSignedPrekey().publicKey());
        assertArrayEquals(original.getSignedPrekeySignature(), loaded.getSignedPrekeySignature());

        // Verify loaded signature
        boolean isValid = dsaService.verify(
                loaded.getSignedPrekey().publicKey(),
                loaded.getSignedPrekeySignature(),
                loaded.getIdentityKey().publicKey()
        );
        assertTrue(isValid);
    }
}
