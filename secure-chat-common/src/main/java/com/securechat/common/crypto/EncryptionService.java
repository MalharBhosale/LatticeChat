package com.securechat.common.crypto;

/**
 * Interface defining authenticated symmetric encryption and decryption operations (e.g. AES-256-GCM).
 */
public interface EncryptionService {

    /**
     * Encrypts plaintext bytes using a symmetric key.
     *
     * @param plaintext the raw bytes to encrypt
     * @param key       the 256-bit symmetric key
     * @param associatedData optional authenticated data (AAD) bound to the ciphertext
     * @return ciphertext package including the IV/nonce, ciphertext bytes, and auth tag
     */
    byte[] encrypt(byte[] plaintext, byte[] key, byte[] associatedData);

    /**
     * Decrypts ciphertext bytes and verifies authentication integrity.
     *
     * @param encryptedData ciphertext package including IV/nonce and auth tag
     * @param key           the 256-bit symmetric key
     * @param associatedData optional authenticated data (AAD) that must match what was used in encryption
     * @return original decrypted plaintext bytes
     */
    byte[] decrypt(byte[] encryptedData, byte[] key, byte[] associatedData);

    /**
     * Returns the algorithm identifier string (e.g., "AES-256-GCM").
     */
    String getAlgorithmName();
}
