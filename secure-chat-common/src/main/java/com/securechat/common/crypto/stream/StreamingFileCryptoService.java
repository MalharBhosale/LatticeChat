package com.securechat.common.crypto.stream;

import com.securechat.common.exception.CryptoException;
import com.securechat.common.exception.MessageDecryptionException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Production-grade streaming file encryption and decryption service using AES-256-GCM AEAD.
 * Implements the LatticeChat Authenticated Stream Container (LTTC v1), chunking files
 * into authenticated blocks with Additional Authenticated Data (AAD) binding to guarantee:
 * <ul>
 *     <li>No memory exhaustion on multi-megabyte / gigabyte files</li>
 *     <li>Cryptographic protection against chunk reordering</li>
 *     <li>Cryptographic protection against chunk truncation or premature stream termination</li>
 *     <li>Unique, deterministic per-chunk 96-bit nonces</li>
 * </ul>
 */
public class StreamingFileCryptoService {

    public static final int MAGIC = 0x4C545443; // "LTTC"
    public static final byte VERSION = 0x01;
    public static final int DEFAULT_CHUNK_SIZE = 64 * 1024; // 64 KB
    public static final int GCM_NONCE_LENGTH = 12; // 96 bits
    public static final int GCM_TAG_LENGTH_BITS = 128; // 16 bytes
    public static final int KEY_LENGTH_BYTES = 32; // 256 bits

    private final SecureRandom secureRandom;

    public StreamingFileCryptoService() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Encrypts an input stream to an output stream using the default 64 KB chunk size.
     */
    public void encryptStream(InputStream in,
                              OutputStream out,
                              byte[] key,
                              long originalFileSize,
                              CryptoProgressListener listener) throws IOException {
        encryptStream(in, out, key, originalFileSize, DEFAULT_CHUNK_SIZE, listener);
    }

    /**
     * Encrypts an input stream to an output stream using authenticated chunk streaming.
     */
    public void encryptStream(InputStream in,
                              OutputStream out,
                              byte[] key,
                              long originalFileSize,
                              int chunkSize,
                              CryptoProgressListener listener) throws IOException {
        validateKey(key);
        if (chunkSize <= 0) {
            throw new IllegalArgumentException("Chunk size must be positive");
        }
        if (listener == null) {
            listener = CryptoProgressListener.NO_OP;
        }

        // 1. Generate random 96-bit base nonce
        byte[] baseNonce = new byte[GCM_NONCE_LENGTH];
        secureRandom.nextBytes(baseNonce);

        DataOutputStream dos = new DataOutputStream(out);

        // 2. Write Header (29 bytes)
        dos.writeInt(MAGIC);
        dos.writeByte(VERSION);
        dos.writeInt(chunkSize);
        dos.write(baseNonce);
        dos.writeLong(originalFileSize);
        dos.flush();

        SecretKey secretKey = new SecretKeySpec(key, "AES");
        byte[] buffer = new byte[chunkSize];
        int chunkIndex = 0;
        long totalBytesRead = 0;

        // Handle empty file edge-case
        if (originalFileSize == 0) {
            byte[] emptyCiphertext = encryptChunk(new byte[0], secretKey, deriveChunkNonce(baseNonce, 0), 0, (byte) 1, 0);
            dos.writeInt(0);
            dos.writeByte(1);
            dos.writeInt(emptyCiphertext.length);
            dos.write(emptyCiphertext);
            dos.flush();
            listener.onProgress(0, 0);
            return;
        }

        InputStream stream = (originalFileSize < 0 && !in.markSupported()) ? new java.io.BufferedInputStream(in) : in;

        while (true) {
            int bytesRead = readFully(stream, buffer);
            if (bytesRead <= 0) {
                break;
            }

            totalBytesRead += bytesRead;
            // Determine if this is the last chunk
            boolean isLast = (originalFileSize >= 0) ? (totalBytesRead >= originalFileSize) : false;
            if (originalFileSize < 0) {
                // Peek if next byte exists
                stream.mark(1);
                int next = stream.read();
                if (next == -1) {
                    isLast = true;
                } else {
                    stream.reset();
                }
            }

            byte isLastFlag = isLast ? (byte) 1 : (byte) 0;
            byte[] chunkPlaintext = (bytesRead == chunkSize) ? buffer : Arrays.copyOf(buffer, bytesRead);
            byte[] chunkNonce = deriveChunkNonce(baseNonce, chunkIndex);

            byte[] ciphertext = encryptChunk(chunkPlaintext, secretKey, chunkNonce, chunkIndex, isLastFlag, originalFileSize);

            dos.writeInt(chunkIndex);
            dos.writeByte(isLastFlag);
            dos.writeInt(ciphertext.length);
            dos.write(ciphertext);
            dos.flush();

            listener.onProgress(totalBytesRead, originalFileSize);
            chunkIndex++;

            if (isLast) {
                break;
            }
        }
    }

    /**
     * Decrypts an authenticated streaming container from an input stream to an output stream.
     * Verifies cryptographic authenticity of each chunk, preventing reordering, truncation, or tampering.
     *
     * @return Total plaintext bytes written
     */
    public long decryptStream(InputStream in,
                              OutputStream out,
                              byte[] key,
                              CryptoProgressListener listener) throws IOException {
        validateKey(key);
        if (listener == null) {
            listener = CryptoProgressListener.NO_OP;
        }

        DataInputStream dis = new DataInputStream(in);

        // 1. Read and validate Header
        int magic = dis.readInt();
        if (magic != MAGIC) {
            throw new CryptoException("Invalid stream magic: expected LTTC (0x" + Integer.toHexString(MAGIC)
                    + ") but found 0x" + Integer.toHexString(magic));
        }

        byte version = dis.readByte();
        if (version != VERSION) {
            throw new CryptoException("Unsupported stream version: " + version + " (expected " + VERSION + ")");
        }

        int chunkSize = dis.readInt();
        if (chunkSize <= 0 || chunkSize > 16 * 1024 * 1024) {
            throw new CryptoException("Illegal chunk size in stream header: " + chunkSize);
        }

        byte[] baseNonce = new byte[GCM_NONCE_LENGTH];
        dis.readFully(baseNonce);

        long originalFileSize = dis.readLong();
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        int expectedChunkIndex = 0;
        long totalDecrypted = 0;
        boolean reachedLastChunk = false;

        while (!reachedLastChunk) {
            int chunkIndex;
            byte isLastByte;
            int ciphertextLength;
            byte[] ciphertext;
            try {
                chunkIndex = dis.readInt();
                isLastByte = dis.readByte();
                ciphertextLength = dis.readInt();
                if (ciphertextLength <= 0 || ciphertextLength > chunkSize + 1024) {
                    throw new CryptoException("Invalid ciphertext length in chunk " + chunkIndex + ": " + ciphertextLength);
                }
                ciphertext = new byte[ciphertextLength];
                dis.readFully(ciphertext);
            } catch (EOFException e) {
                if (!reachedLastChunk) {
                    throw new CryptoException("Truncated stream: stream ended before final chunk was received", e);
                }
                break;
            }

            // Cryptographic check: Chunk reordering defense
            if (chunkIndex != expectedChunkIndex) {
                throw new CryptoException("Chunk reordering attack detected: expected chunk " + expectedChunkIndex
                        + " but found " + chunkIndex);
            }

            byte[] chunkNonce = deriveChunkNonce(baseNonce, chunkIndex);
            byte[] plaintext = decryptChunk(ciphertext, secretKey, chunkNonce, chunkIndex, isLastByte, originalFileSize);

            out.write(plaintext);
            totalDecrypted += plaintext.length;
            listener.onProgress(totalDecrypted, originalFileSize);

            expectedChunkIndex++;
            if (isLastByte == 1) {
                reachedLastChunk = true;
            }
        }

        out.flush();

        if (originalFileSize >= 0 && totalDecrypted != originalFileSize) {
            throw new CryptoException("Decrypted size mismatch: expected " + originalFileSize + " bytes, but got " + totalDecrypted);
        }

        return totalDecrypted;
    }

    /**
     * Helper to encrypt a file on disk directly to an encrypted file.
     */
    public void encryptFile(File sourceFile, File targetFile, byte[] key, CryptoProgressListener listener) throws IOException {
        if (!sourceFile.exists() || !sourceFile.canRead()) {
            throw new IllegalArgumentException("Source file cannot be read: " + sourceFile.getAbsolutePath());
        }
        if (targetFile.getParentFile() != null) {
            targetFile.getParentFile().mkdirs();
        }

        try (InputStream in = new FileInputStream(sourceFile);
             OutputStream out = new FileOutputStream(targetFile)) {
            encryptStream(in, out, key, sourceFile.length(), listener);
        }
    }

    /**
     * Helper to decrypt an encrypted file on disk directly to a plaintext file.
     */
    public long decryptFile(File sourceFile, File targetFile, byte[] key, CryptoProgressListener listener) throws IOException {
        if (!sourceFile.exists() || !sourceFile.canRead()) {
            throw new IllegalArgumentException("Encrypted source file cannot be read: " + sourceFile.getAbsolutePath());
        }
        if (targetFile.getParentFile() != null) {
            targetFile.getParentFile().mkdirs();
        }

        try (InputStream in = new FileInputStream(sourceFile);
             OutputStream out = new FileOutputStream(targetFile)) {
            return decryptStream(in, out, key, listener);
        }
    }

    private byte[] encryptChunk(byte[] plaintext,
                                SecretKey key,
                                byte[] nonce,
                                int chunkIndex,
                                byte isLast,
                                long originalFileSize) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce));
            cipher.updateAAD(buildAad(chunkIndex, isLast, originalFileSize));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoException("Failed to encrypt chunk " + chunkIndex + ": " + e.getMessage(), e);
        }
    }

    private byte[] decryptChunk(byte[] ciphertext,
                                SecretKey key,
                                byte[] nonce,
                                int chunkIndex,
                                byte isLast,
                                long originalFileSize) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce));
            cipher.updateAAD(buildAad(chunkIndex, isLast, originalFileSize));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new MessageDecryptionException("Chunk " + chunkIndex + " authentication tag verification failed: "
                    + "data has been tampered with or corrupted", e);
        }
    }

    /**
     * Binds Additional Authenticated Data (AAD) to chunk index, last chunk flag, and file size.
     */
    public static byte[] buildAad(int chunkIndex, byte isLast, long originalFileSize) {
        return ByteBuffer.allocate(13)
                .putInt(chunkIndex)
                .put(isLast)
                .putLong(originalFileSize)
                .array();
    }

    /**
     * Derives a deterministic, unique 96-bit nonce per chunk without state collision.
     */
    public static byte[] deriveChunkNonce(byte[] baseNonce, int chunkIndex) {
        byte[] nonce = Arrays.copyOf(baseNonce, GCM_NONCE_LENGTH);
        nonce[8]  ^= (byte) ((chunkIndex >>> 24) & 0xFF);
        nonce[9]  ^= (byte) ((chunkIndex >>> 16) & 0xFF);
        nonce[10] ^= (byte) ((chunkIndex >>> 8) & 0xFF);
        nonce[11] ^= (byte) (chunkIndex & 0xFF);
        return nonce;
    }

    private static int readFully(InputStream in, byte[] buffer) throws IOException {
        int offset = 0;
        while (offset < buffer.length) {
            int read = in.read(buffer, offset, buffer.length - offset);
            if (read == -1) {
                break;
            }
            offset += read;
        }
        return offset;
    }

    private static void validateKey(byte[] key) {
        if (key == null || key.length != KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException("AES-256 requires a 32-byte key (got "
                    + (key == null ? "null" : key.length + " bytes") + ")");
        }
    }
}
