package com.securechat.common.crypto;

/**
 * Interface defining Post-Quantum Digital Signature operations (e.g. ML-DSA / FIPS 204).
 */
public interface SignatureService {

    /**
     * Represents a keypair for post-quantum digital signatures.
     */
    record SignatureKeyPair(byte[] publicKey, byte[] privateKey, String parameterSet) {}

    /**
     * Generates a new post-quantum signature keypair.
     */
    SignatureKeyPair generateKeyPair();

    /**
     * Signs a message payload with the signer's private key.
     *
     * @param message the byte payload to sign
     * @param privateKey the signer's private key
     * @return the raw signature bytes
     */
    byte[] sign(byte[] message, byte[] privateKey);

    /**
     * Verifies a digital signature against a message and the signer's public key.
     *
     * @param message the message that was signed
     * @param signature the signature bytes to verify
     * @param publicKey the signer's public key
     * @return true if valid and authentic, false otherwise
     */
    boolean verify(byte[] message, byte[] signature, byte[] publicKey);

    /**
     * Returns the algorithm/parameter identifier string (e.g., "ML-DSA-65").
     */
    String getAlgorithmName();
}
