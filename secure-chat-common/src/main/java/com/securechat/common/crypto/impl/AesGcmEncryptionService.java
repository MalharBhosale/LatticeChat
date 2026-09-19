package com.securechat.common.crypto.impl;

import com.securechat.common.crypto.EncryptionService;
import com.securechat.common.exception.CryptoException;
import com.securechat.common.exception.MessageDecryptionException;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implementation of {@link EncryptionService} using NIST SP 800-38D AES-256-GCM
 * (Galois/Counter Mode).
 *
 * Provides authenticated encryption with associated data (AEAD).
 * Guarantees both confidentiality and authenticity/integrity.
 */
public class AesGcmEncryptionService implements EncryptionService {

    public static final String TRANSFORMATION = "AES/GCM/NoPadding";
    public static final int KEY_LENGTH_BYTES = 32; // 256-bit AES
    public static final int IV_LENGTH_BYTES = 12;  // 96-bit standard GCM nonce
    public static final int TAG_LENGTH_BITS = 128; // 128-bit authentication tag
    public static final int TAG_LENGTH_BYTES = 16;

    private final SecureRandom secureRandom;

    public AesGcmEncryptionService() {
        this.secureRandom = new SecureRandom();
    }

    public AesGcmEncryptionService(SecureRandom secureRandom) {
        this.secureRandom = secureRandom != null ? secureRandom : new SecureRandom();
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] key, byte[] associatedData) {
        if (plaintext == null) {
            throw new CryptoException("Plaintext must not be null");
        }
        validateKey(key);

        try {
            // Generate a fresh, unpredictable 96-bit nonce for every encryption
            byte[] iv = new byte[IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            if (associatedData != null && associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }

            byte[] ciphertextWithTag = cipher.doFinal(plaintext);

            // Package output as: [12-byte IV] + [Ciphertext + 16-byte Tag]
            ByteBuffer buffer = ByteBuffer.allocate(IV_LENGTH_BYTES + ciphertextWithTag.length);
            buffer.put(iv);
            buffer.put(ciphertextWithTag);

            return buffer.array();
        } catch (Exception e) {
            throw new CryptoException("AES-GCM encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] key, byte[] associatedData) {
        if (encryptedData == null) {
            throw new CryptoException("Encrypted data must not be null");
        }
        if (encryptedData.length < IV_LENGTH_BYTES + TAG_LENGTH_BYTES) {
            throw new MessageDecryptionException("Ciphertext payload is truncated or invalid");
        }
        validateKey(key);

        try {
            // Extract the 12-byte IV from the front
            byte[] iv = Arrays.copyOfRange(encryptedData, 0, IV_LENGTH_BYTES);
            byte[] ciphertextWithTag = Arrays.copyOfRange(encryptedData, IV_LENGTH_BYTES, encryptedData.length);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            if (associatedData != null && associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }

            return cipher.doFinal(ciphertextWithTag);
        } catch (AEADBadTagException e) {
            throw new MessageDecryptionException("Authentication tag verification failed: message has been tampered with or corrupted", e);
        } catch (Exception e) {
            throw new MessageDecryptionException("AES-GCM decryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public String getAlgorithmName() {
        return "AES-256-GCM";
    }

    private void validateKey(byte[] key) {
        if (key == null || key.length != KEY_LENGTH_BYTES) {
            throw new CryptoException("AES-256 key must be exactly 32 bytes (256 bits) in length");
        }
    }
}
