package com.securechat.common.crypto;

/**
 * Interface defining Key Derivation Function operations (e.g. HKDF / RFC 5869).
 */
public interface KeyDerivationService {

    /**
     * Derives a cryptographic session key from input keying material (IKM).
     *
     * @param inputKeyMaterial the raw shared secret (e.g. from ML-KEM)
     * @param salt optional salt value (non-secret random value, improves randomness extraction)
     * @param info optional context and application-specific information string
     * @param outputLengthBytes length of output key material in bytes (e.g., 32 for AES-256)
     * @return cryptographically strong derived key bytes
     */
    byte[] deriveKey(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLengthBytes);

    /**
     * Returns the algorithm identifier string (e.g., "HKDF-SHA256").
     */
    String getAlgorithmName();
}
