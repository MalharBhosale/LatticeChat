package com.securechat.common.crypto.stream;

import com.securechat.common.exception.CryptoException;
import com.securechat.common.exception.MessageDecryptionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class StreamingFileCryptoTest {

    private StreamingFileCryptoService cryptoService;
    private byte[] key;
    private final SecureRandom random = new SecureRandom();

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        cryptoService = new StreamingFileCryptoService();
        key = new byte[32];
        random.nextBytes(key);
    }

    @Test
    @DisplayName("Should successfully encrypt and decrypt stream roundtrip for arbitrary byte lengths")
    void testRoundtripStreamingSmallAndMedium() throws IOException {
        String testData = "LatticeChat Post-Quantum Zero-Knowledge Encrypted Streaming Content! ".repeat(100);
        byte[] plaintext = testData.getBytes(StandardCharsets.UTF_8);

        ByteArrayInputStream in = new ByteArrayInputStream(plaintext);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        AtomicLong progressCounter = new AtomicLong();
        cryptoService.encryptStream(in, out, key, plaintext.length, 1024, (processed, total) -> progressCounter.set(processed));

        byte[] ciphertext = out.toByteArray();
        assertTrue(ciphertext.length > plaintext.length);
        assertEquals(plaintext.length, progressCounter.get());

        // Decrypt
        ByteArrayInputStream cipherIn = new ByteArrayInputStream(ciphertext);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        long decryptedBytes = cryptoService.decryptStream(cipherIn, plainOut, key, null);

        assertEquals(plaintext.length, decryptedBytes);
        assertArrayEquals(plaintext, plainOut.toByteArray());
    }

    @Test
    @DisplayName("Should encrypt and decrypt multi-chunk files on disk with progress tracking")
    void testFileEncryptionAndDecryptionOnDisk() throws IOException {
        // Create 256 KB test file
        byte[] largeData = new byte[256 * 1024];
        random.nextBytes(largeData);

        Path srcPath = tempDir.resolve("original.dat");
        Path encPath = tempDir.resolve("encrypted.lttc");
        Path decPath = tempDir.resolve("decrypted.dat");

        Files.write(srcPath, largeData);

        AtomicLong encProgress = new AtomicLong();
        cryptoService.encryptFile(srcPath.toFile(), encPath.toFile(), key, (proc, tot) -> encProgress.set(proc));
        assertEquals(largeData.length, encProgress.get());
        assertTrue(Files.exists(encPath));

        AtomicLong decProgress = new AtomicLong();
        long written = cryptoService.decryptFile(encPath.toFile(), decPath.toFile(), key, (proc, tot) -> decProgress.set(proc));
        assertEquals(largeData.length, written);
        assertEquals(largeData.length, decProgress.get());

        byte[] recovered = Files.readAllBytes(decPath);
        assertArrayEquals(largeData, recovered);
    }

    @Test
    @DisplayName("Should handle empty file streams correctly")
    void testEmptyStream() throws IOException {
        byte[] empty = new byte[0];
        ByteArrayInputStream in = new ByteArrayInputStream(empty);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        cryptoService.encryptStream(in, out, key, 0, null);
        byte[] ciphertext = out.toByteArray();

        ByteArrayInputStream cipherIn = new ByteArrayInputStream(ciphertext);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        long decrypted = cryptoService.decryptStream(cipherIn, plainOut, key, null);

        assertEquals(0, decrypted);
        assertEquals(0, plainOut.size());
    }

    @Test
    @DisplayName("Should detect and reject ciphertext bit flips with MessageDecryptionException")
    void testTamperedCiphertextRejection() throws IOException {
        byte[] plaintext = "Sensitive cryptographic document payload".getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        cryptoService.encryptStream(new ByteArrayInputStream(plaintext), out, key, plaintext.length, 1024, null);
        byte[] ciphertext = out.toByteArray();

        // Flip bit in chunk body (header 29B + chunk index 4B + isLast 1B + length 4B = 38B)
        ciphertext[40] ^= 0xFF;

        ByteArrayInputStream tamperedIn = new ByteArrayInputStream(ciphertext);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        assertThrows(MessageDecryptionException.class, () ->
                cryptoService.decryptStream(tamperedIn, plainOut, key, null));
    }

    @Test
    @DisplayName("Should reject corrupted magic or header version with CryptoException")
    void testCorruptedHeaderMagic() throws IOException {
        byte[] plaintext = "Hello World".getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        cryptoService.encryptStream(new ByteArrayInputStream(plaintext), out, key, plaintext.length, null);
        byte[] ciphertext = out.toByteArray();

        // Corrupt magic bytes
        ciphertext[0] = 0x00;

        ByteArrayInputStream corruptedIn = new ByteArrayInputStream(ciphertext);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        assertThrows(CryptoException.class, () ->
                cryptoService.decryptStream(corruptedIn, plainOut, key, null));
    }

    @Test
    @DisplayName("Should detect and reject truncated stream with CryptoException")
    void testTruncatedStreamRejection() throws IOException {
        byte[] data = new byte[128 * 1024]; // 2 chunks with 64KB chunk size
        random.nextBytes(data);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        cryptoService.encryptStream(new ByteArrayInputStream(data), out, key, data.length, 64 * 1024, null);
        byte[] fullCiphertext = out.toByteArray();

        // Truncate the stream halfway (cutting off final chunk)
        byte[] truncatedCiphertext = new byte[fullCiphertext.length / 2];
        System.arraycopy(fullCiphertext, 0, truncatedCiphertext, 0, truncatedCiphertext.length);

        ByteArrayInputStream truncatedIn = new ByteArrayInputStream(truncatedCiphertext);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        assertThrows(CryptoException.class, () ->
                cryptoService.decryptStream(truncatedIn, plainOut, key, null));
    }
}
