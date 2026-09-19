package com.securechat.common.crypto.impl;

import com.securechat.common.crypto.KeyExchangeService;
import com.securechat.common.exception.CryptoException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * Implementation of {@link KeyExchangeService} using NIST FIPS 203 ML-KEM
 * (Module-Lattice-Based Key-Encapsulation Mechanism).
 *
 * Provides IND-CCA2 security against both classical and quantum adversaries.
 */
public class MlKemKeyExchangeService implements KeyExchangeService {

    private final MLKEMParameters parameters;
    private final String algorithmName;
    private final SecureRandom secureRandom;

    /**
     * Default constructor initializes ML-KEM-768 (NIST Security Category 3, ~128-bit quantum security).
     */
    public MlKemKeyExchangeService() {
        this(MLKEMParameters.ml_kem_768, "ML-KEM-768");
    }

    public MlKemKeyExchangeService(MLKEMParameters parameters, String algorithmName) {
        this.parameters = Objects.requireNonNull(parameters, "parameters must not be null");
        this.algorithmName = Objects.requireNonNull(algorithmName, "algorithmName must not be null");
        this.secureRandom = new SecureRandom();
    }

    /**
     * Factory method for ML-KEM-768 (Recommended default).
     */
    public static MlKemKeyExchangeService mlKem768() {
        return new MlKemKeyExchangeService(MLKEMParameters.ml_kem_768, "ML-KEM-768");
    }

    /**
     * Factory method for ML-KEM-1024 (Highest security level, NIST Category 5).
     */
    public static MlKemKeyExchangeService mlKem1024() {
        return new MlKemKeyExchangeService(MLKEMParameters.ml_kem_1024, "ML-KEM-1024");
    }

    @Override
    public KemKeyPair generateKeyPair() {
        try {
            MLKEMKeyPairGenerator keyPairGen = new MLKEMKeyPairGenerator();
            keyPairGen.init(new MLKEMKeyGenerationParameters(secureRandom, parameters));

            AsymmetricCipherKeyPair keyPair = keyPairGen.generateKeyPair();
            MLKEMPublicKeyParameters publicKey = (MLKEMPublicKeyParameters) keyPair.getPublic();
            MLKEMPrivateKeyParameters privateKey = (MLKEMPrivateKeyParameters) keyPair.getPrivate();

            return new KemKeyPair(publicKey.getEncoded(), privateKey.getEncoded(), algorithmName);
        } catch (Exception e) {
            throw new CryptoException("Failed to generate ML-KEM keypair: " + e.getMessage(), e);
        }
    }

    @Override
    public KemSecret encapsulate(byte[] recipientPublicKey) {
        if (recipientPublicKey == null || recipientPublicKey.length == 0) {
            throw new CryptoException("Recipient public key must not be null or empty");
        }

        try {
            MLKEMPublicKeyParameters pubParams = new MLKEMPublicKeyParameters(parameters, recipientPublicKey);
            MLKEMGenerator generator = new MLKEMGenerator(secureRandom);
            SecretWithEncapsulation secretWithEncapsulation = generator.generateEncapsulated(pubParams);

            byte[] encapsulationCiphertext = secretWithEncapsulation.getEncapsulation();
            byte[] sharedSecret = secretWithEncapsulation.getSecret();

            return new KemSecret(encapsulationCiphertext, sharedSecret);
        } catch (Exception e) {
            throw new CryptoException("ML-KEM encapsulation failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decapsulate(byte[] privateKey, byte[] encapsulationCiphertext) {
        if (privateKey == null || privateKey.length == 0) {
            throw new CryptoException("Private key must not be null or empty");
        }
        if (encapsulationCiphertext == null || encapsulationCiphertext.length == 0) {
            throw new CryptoException("Encapsulation ciphertext must not be null or empty");
        }

        try {
            MLKEMPrivateKeyParameters privParams = new MLKEMPrivateKeyParameters(parameters, privateKey);
            MLKEMExtractor extractor = new MLKEMExtractor(privParams);
            return extractor.extractSecret(encapsulationCiphertext);
        } catch (Exception e) {
            throw new CryptoException("ML-KEM decapsulation failed: " + e.getMessage(), e);
        }
    }

    @Override
    public String getAlgorithmName() {
        return algorithmName;
    }
}
