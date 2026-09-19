package com.securechat.client.crypto;

import com.securechat.common.exception.CryptoException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class FileCryptoTest {

    private final FileCryptoService fileCryptoService = new FileCryptoService();

    @Test
    @DisplayName("Should encrypt and decrypt byte payload with AES-256-GCM successfully")
    void testBytesEncryptionRoundtrip() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        byte[] plaintext = "Highly sensitive post-quantum message attachment contents".getBytes(StandardCharsets.UTF_8);

        var payload = fileCryptoService.encryptBytes(plaintext, key, "confidential.txt", "text/plain");

        assertNotNull(payload);
        assertNotNull(payload.ciphertext());
        assertEquals(12, payload.nonce().length);
        assertEquals("confidential.txt", payload.filename());

        byte[] decrypted = fileCryptoService.decryptBytes(payload.ciphertext(), payload.nonce(), key);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName("Should encrypt file to disk and decrypt back matching exact original contents")
    void testFileEncryptionRoundtrip(@TempDir Path tempDir) throws IOException {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        Path sourcePath = tempDir.resolve("original_report.pdf");
        byte[] sampleData = new byte[65536]; // 64 KB
        new SecureRandom().nextBytes(sampleData);
        Files.write(sourcePath, sampleData);

        var payload = fileCryptoService.encryptFile(sourcePath.toFile(), key);

        Path decryptedPath = tempDir.resolve("decrypted_report.pdf");
        fileCryptoService.decryptToFile(payload.ciphertext(), payload.nonce(), key, decryptedPath.toFile());

        assertTrue(Files.exists(decryptedPath));
        byte[] restoredBytes = Files.readAllBytes(decryptedPath);
        assertArrayEquals(sampleData, restoredBytes);
    }

    @Test
    @DisplayName("Tampered ciphertext should fail GCM authentication and throw CryptoException")
    void testTamperedCiphertextFailsAuthentication() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        byte[] plaintext = "Tamper check text".getBytes(StandardCharsets.UTF_8);
        var payload = fileCryptoService.encryptBytes(plaintext, key, "data.bin", "application/octet-stream");

        // Tamper with 1 byte of ciphertext
        byte[] tamperedCiphertext = payload.ciphertext().clone();
        tamperedCiphertext[tamperedCiphertext.length - 1] ^= 0xFF;

        assertThrows(CryptoException.class, () ->
                fileCryptoService.decryptBytes(tamperedCiphertext, payload.nonce(), key)
        );
    }

    @Test
    @DisplayName("Invalid key size should throw IllegalArgumentException")
    void testInvalidKeySize() {
        byte[] badKey = new byte[16]; // Only 128 bits
        byte[] plaintext = "Hello".getBytes();

        assertThrows(IllegalArgumentException.class, () ->
                fileCryptoService.encryptBytes(plaintext, badKey, "f.txt", "text/plain")
        );
    }

    @Test
    @DisplayName("Should encrypt and decrypt using authenticated streaming chunking matching exact contents")
    void testStreamingFileEncryptionRoundtrip(@TempDir Path tempDir) throws IOException {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        Path sourcePath = tempDir.resolve("stream_source.bin");
        byte[] largeData = new byte[192 * 1024]; // 192 KB (3 chunks)
        new SecureRandom().nextBytes(largeData);
        Files.write(sourcePath, largeData);

        Path encPath = tempDir.resolve("stream_enc.lttc");
        Path decPath = tempDir.resolve("stream_dec.bin");

        fileCryptoService.encryptFileStreaming(sourcePath.toFile(), encPath.toFile(), key, null);
        assertTrue(Files.exists(encPath));

        long decryptedBytes = fileCryptoService.decryptFileStreaming(encPath.toFile(), decPath.toFile(), key, null);
        assertEquals(largeData.length, decryptedBytes);

        byte[] recovered = Files.readAllBytes(decPath);
        assertArrayEquals(largeData, recovered);
    }
}
