package com.securechat.common.crypto.impl;

import com.securechat.common.crypto.KeyDerivationService;
import com.securechat.common.exception.CryptoException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Implementation of {@link KeyDerivationService} using RFC 5869 HKDF-SHA256
 * (HMAC-based Extract-and-Expand Key Derivation Function).
 *
 * Used to expand non-uniform or post-quantum shared secrets into cryptographically
 * strong symmetric keys suitable for AES-256-GCM.
 */
public class HkdfKeyDerivationService implements KeyDerivationService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int HASH_OUTPUT_LEN = 32; // SHA-256 output length in bytes

    @Override
    public byte[] deriveKey(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLengthBytes) {
        if (inputKeyMaterial == null || inputKeyMaterial.length == 0) {
            throw new CryptoException("Input Key Material (IKM) must not be null or empty");
        }
        if (outputLengthBytes <= 0 || outputLengthBytes > 255 * HASH_OUTPUT_LEN) {
            throw new CryptoException("Output length must be between 1 and " + (255 * HASH_OUTPUT_LEN) + " bytes");
        }

        try {
            // Step 1: HKDF-Extract
            byte[] prk = extract(salt, inputKeyMaterial);

            // Step 2: HKDF-Expand
            return expand(prk, info, outputLengthBytes);
        } catch (Exception e) {
            throw new CryptoException("HKDF key derivation failed: " + e.getMessage(), e);
        }
    }

    @Override
    public String getAlgorithmName() {
        return "HKDF-SHA256";
    }

    /**
     * HKDF-Extract(salt, IKM) -> PRK
     */
    private byte[] extract(byte[] salt, byte[] ikm) throws Exception {
        if (salt == null || salt.length == 0) {
            salt = new byte[HASH_OUTPUT_LEN]; // String of 32 zeros per RFC 5869 §2.2
        }

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(salt, HMAC_ALGORITHM));
        return mac.doFinal(ikm);
    }

    /**
     * HKDF-Expand(PRK, info, L) -> OKM
     */
    private byte[] expand(byte[] prk, byte[] info, int outputLengthBytes) throws Exception {
        if (info == null) {
            info = new byte[0];
        }

        int numBlocks = (int) Math.ceil((double) outputLengthBytes / HASH_OUTPUT_LEN);
        ByteArrayOutputStream okm = new ByteArrayOutputStream();
        byte[] currentBlock = new byte[0];

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(prk, HMAC_ALGORITHM));

        for (int i = 1; i <= numBlocks; i++) {
            mac.reset();
            mac.update(currentBlock);
            mac.update(info);
            mac.update((byte) i);
            currentBlock = mac.doFinal();

            okm.write(currentBlock);
        }

        return Arrays.copyOf(okm.toByteArray(), outputLengthBytes);
    }
}
