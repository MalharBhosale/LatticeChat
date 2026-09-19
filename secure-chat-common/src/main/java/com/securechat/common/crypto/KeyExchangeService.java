package com.securechat.common.crypto;

/**
 * Interface defining Post-Quantum Key Encapsulation Mechanism (KEM) operations (e.g. ML-KEM / FIPS 203).
 */
public interface KeyExchangeService {

    /**
     * Represents an asymmetric keypair for post-quantum key establishment.
     */
    record KemKeyPair(byte[] publicKey, byte[] privateKey, String parameterSet) {}

    /**
     * Represents the result of an encapsulation operation: the ciphertext sent to the peer
     * and the shared secret established locally.
     */
    record KemSecret(byte[] encapsulationCiphertext, byte[] sharedSecret) {}

    /**
     * Generates a new post-quantum KEM keypair.
     */
    KemKeyPair generateKeyPair();

    /**
     * Encapsulates a fresh shared secret against the recipient's public key.
     *
     * @param recipientPublicKey the public key of the receiving peer
     * @return the encapsulation ciphertext to transmit and the established shared secret
     */
    KemSecret encapsulate(byte[] recipientPublicKey);

    /**
     * Decapsulates the shared secret using the recipient's private key and the incoming ciphertext.
     *
     * @param privateKey the private key of the recipient
     * @param encapsulationCiphertext the ciphertext received from the sender
     * @return the recovered shared secret (must match sender's shared secret)
     */
    byte[] decapsulate(byte[] privateKey, byte[] encapsulationCiphertext);

    /**
     * Returns the algorithm/parameter identifier string (e.g., "ML-KEM-768").
     */
    String getAlgorithmName();
}
