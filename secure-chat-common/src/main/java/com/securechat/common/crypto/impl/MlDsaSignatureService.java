package com.securechat.common.crypto.impl;

import com.securechat.common.crypto.SignatureService;
import com.securechat.common.exception.CryptoException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * Implementation of {@link SignatureService} using NIST FIPS 204 ML-DSA
 * (Module-Lattice-Based Digital Signature Algorithm).
 *
 * Provides EUF-CMA (existential unforgeability under chosen message attack)
 * against both classical and quantum adversaries.
 */
public class MlDsaSignatureService implements SignatureService {

    private final MLDSAParameters parameters;
    private final String algorithmName;
    private final SecureRandom secureRandom;

    /**
     * Default constructor initializes ML-DSA-65 (NIST Security Category 3, ~128-bit quantum security).
     */
    public MlDsaSignatureService() {
        this(MLDSAParameters.ml_dsa_65, "ML-DSA-65");
    }

    public MlDsaSignatureService(MLDSAParameters parameters, String algorithmName) {
        this.parameters = Objects.requireNonNull(parameters, "parameters must not be null");
        this.algorithmName = Objects.requireNonNull(algorithmName, "algorithmName must not be null");
        this.secureRandom = new SecureRandom();
    }

    /**
     * Factory method for ML-DSA-65 (Recommended default).
     */
    public static MlDsaSignatureService mlDsa65() {
        return new MlDsaSignatureService(MLDSAParameters.ml_dsa_65, "ML-DSA-65");
    }

    /**
     * Factory method for ML-DSA-87 (Highest security level, NIST Category 5).
     */
    public static MlDsaSignatureService mlDsa87() {
        return new MlDsaSignatureService(MLDSAParameters.ml_dsa_87, "ML-DSA-87");
    }

    @Override
    public SignatureKeyPair generateKeyPair() {
        try {
            MLDSAKeyPairGenerator keyPairGen = new MLDSAKeyPairGenerator();
            keyPairGen.init(new MLDSAKeyGenerationParameters(secureRandom, parameters));

            AsymmetricCipherKeyPair keyPair = keyPairGen.generateKeyPair();
            MLDSAPublicKeyParameters publicKey = (MLDSAPublicKeyParameters) keyPair.getPublic();
            MLDSAPrivateKeyParameters privateKey = (MLDSAPrivateKeyParameters) keyPair.getPrivate();

            return new SignatureKeyPair(publicKey.getEncoded(), privateKey.getEncoded(), algorithmName);
        } catch (Exception e) {
            throw new CryptoException("Failed to generate ML-DSA keypair: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] sign(byte[] message, byte[] privateKey) {
        if (message == null) {
            throw new CryptoException("Message payload to sign must not be null");
        }
        if (privateKey == null || privateKey.length == 0) {
            throw new CryptoException("Private key must not be null or empty");
        }

        try {
            MLDSAPrivateKeyParameters privParams = new MLDSAPrivateKeyParameters(parameters, privateKey);
            MLDSASigner signer = new MLDSASigner();
            signer.init(true, privParams);
            signer.update(message, 0, message.length);
            return signer.generateSignature();
        } catch (Exception e) {
            throw new CryptoException("ML-DSA signature generation failed: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean verify(byte[] message, byte[] signature, byte[] publicKey) {
        if (message == null || signature == null || publicKey == null) {
            return false;
        }

        try {
            MLDSAPublicKeyParameters pubParams = new MLDSAPublicKeyParameters(parameters, publicKey);
            MLDSASigner signer = new MLDSASigner();
            signer.init(false, pubParams);
            signer.update(message, 0, message.length);
            return signer.verifySignature(signature);
        } catch (Exception e) {
            // Constant-time failure semantics on malformed inputs
            return false;
        }
    }

    @Override
    public String getAlgorithmName() {
        return algorithmName;
    }
}
