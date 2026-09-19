package com.securechat.common.crypto.stream;

/**
 * Functional callback interface for tracking cryptographic streaming progress.
 */
@FunctionalInterface
public interface CryptoProgressListener {

    /**
     * Called periodically as bytes are encrypted or decrypted.
     *
     * @param bytesProcessed Number of plaintext bytes processed so far
     * @param totalBytes     Total expected plaintext bytes (-1 if unknown)
     */
    void onProgress(long bytesProcessed, long totalBytes);

    /**
     * No-op progress listener instance.
     */
    CryptoProgressListener NO_OP = (processed, total) -> {};
}
