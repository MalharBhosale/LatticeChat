package com.securechat.client.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class ClientKeystoreTest {

    @BeforeAll
    static void initBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    @DisplayName("Should generate valid post-quantum keys and encrypt/decrypt from disk with master password")
    void testGenerateSaveAndLoad(@TempDir Path tempDir) throws Exception {
        ClientKeystore keystore = ClientKeystore.generateNew(5);

        assertNotNull(keystore.getIdentityKey());
        assertNotNull(keystore.getSignedPrekey());
        assertNotNull(keystore.getSignedPrekeySignature());
        assertEquals(5, keystore.getOneTimePrekeys().size());

        File file = tempDir.resolve("test_keystore.enc").toFile();
        char[] password = "SecretMasterPassword123!".toCharArray();

        // Encrypt and save
        keystore.saveToFile(file, password);
        assertTrue(file.exists());
        assertTrue(file.length() > 0);

        // Load and decrypt with correct password
        ClientKeystore loaded = ClientKeystore.loadFromFile(file, password);
        assertArrayEquals(keystore.getIdentityKey().publicKey(), loaded.getIdentityKey().publicKey());
        assertArrayEquals(keystore.getIdentityKey().privateKey(), loaded.getIdentityKey().privateKey());
        assertArrayEquals(keystore.getSignedPrekey().publicKey(), loaded.getSignedPrekey().publicKey());
        assertArrayEquals(keystore.getSignedPrekeySignature(), loaded.getSignedPrekeySignature());
        assertEquals(5, loaded.getOneTimePrekeys().size());

        // Attempt load with wrong password should fail
        char[] wrongPassword = "WrongPassword".toCharArray();
        assertThrows(Exception.class, () -> ClientKeystore.loadFromFile(file, wrongPassword));
    }

    @Test
    @DisplayName("Should consume one-time prekey by ID")
    void testConsumeOneTimePrekey() {
        ClientKeystore keystore = ClientKeystore.generateNew(3);
        assertEquals(3, keystore.getOneTimePrekeys().size());

        var opk1 = keystore.consumeOneTimePrekey(1L);
        assertNotNull(opk1);
        assertEquals(2, keystore.getOneTimePrekeys().size());
        assertNull(keystore.getOneTimePrekey(1L));
    }
}
