package com.securechat.client.crypto;

import com.securechat.common.crypto.EncryptionService;
import com.securechat.common.crypto.impl.AesGcmEncryptionService;
import com.securechat.common.exception.CryptoException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Service managing client-side file encryption and decryption via AES-256-GCM.
 * All files are encrypted with the peer's active post-quantum session key before transmission.
 */
public class FileCryptoService {

    private static final int GCM_IV_LENGTH_BYTES = 12; // 96-bit nonce
    private final EncryptionService encryptionService;
    private final SecureRandom secureRandom;

    public FileCryptoService() {
        this.encryptionService = new AesGcmEncryptionService();
        this.secureRandom = new SecureRandom();
    }

    /**
     * Encrypts a file using AES-256-GCM with a unique 96-bit random nonce.
     * Returns an EncryptedFilePayload containing the ciphertext (with GCM tag) and nonce.
     */
    public EncryptedFilePayload encryptFile(File file, byte[] sessionKey) throws IOException {
        if (!file.exists() || !file.canRead()) {
            throw new IllegalArgumentException("Cannot read file: " + file.getAbsolutePath());
        }

        byte[] plaintextBytes = Files.readAllBytes(file.toPath());
        String mimeType = Files.probeContentType(file.toPath());
        if (mimeType == null || mimeType.isBlank()) {
            mimeType = "application/octet-stream";
        }

        return encryptBytes(plaintextBytes, sessionKey, file.getName(), mimeType);
    }

    /**
     * Encrypts raw byte content using AES-256-GCM.
     */
    public EncryptedFilePayload encryptBytes(byte[] plaintextBytes, byte[] sessionKey, String filename, String mimeType) {
        if (sessionKey == null || sessionKey.length != 32) {
            throw new IllegalArgumentException("AES-256 requires a 32-byte key");
        }

        // AesGcmEncryptionService.encrypt prefixes ciphertext with the 12-byte IV
        byte[] encryptedPackage = encryptionService.encrypt(plaintextBytes, sessionKey, null);

        byte[] iv = Arrays.copyOfRange(encryptedPackage, 0, GCM_IV_LENGTH_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(encryptedPackage, GCM_IV_LENGTH_BYTES, encryptedPackage.length);

        return new EncryptedFilePayload(ciphertext, iv, filename, mimeType, plaintextBytes.length);
    }

    /**
     * Decrypts ciphertext bytes with AES-256-GCM using the session key and nonce.
     * Validates the 128-bit authentication tag.
     */
    public byte[] decryptBytes(byte[] ciphertext, byte[] nonce, byte[] sessionKey) {
        if (sessionKey == null || sessionKey.length != 32) {
            throw new IllegalArgumentException("AES-256 requires a 32-byte key");
        }
        if (nonce == null || nonce.length != GCM_IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("GCM requires a 12-byte IV");
        }

        byte[] combinedPackage = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, combinedPackage, 0, nonce.length);
        System.arraycopy(ciphertext, 0, combinedPackage, nonce.length, ciphertext.length);

        return encryptionService.decrypt(combinedPackage, sessionKey, null);
    }

    /**
     * Decrypts ciphertext and writes the resulting plaintext to an output file.
     */
    public void decryptToFile(byte[] ciphertext, byte[] nonce, byte[] sessionKey, File destinationFile) throws IOException {
        byte[] decryptedBytes = decryptBytes(ciphertext, nonce, sessionKey);
        if (destinationFile.getParentFile() != null) {
            destinationFile.getParentFile().mkdirs();
        }
        Files.write(destinationFile.toPath(), decryptedBytes);
    }

    public record EncryptedFilePayload(
            byte[] ciphertext,
            byte[] nonce,
            String filename,
            String mimeType,
            long originalSize
    ) {}
}
