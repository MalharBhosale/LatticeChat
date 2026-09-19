package com.securechat.client.protocol;

import com.securechat.client.crypto.ClientKeystore;
import com.securechat.client.storage.LocalStorageService;
import com.securechat.client.storage.LocalMessage;
import com.securechat.common.crypto.EncryptionService;
import com.securechat.common.crypto.KeyDerivationService;
import com.securechat.common.crypto.KeyExchangeService;
import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.KeyExchangeService.KemSecret;
import com.securechat.common.crypto.SignatureService;
import com.securechat.common.crypto.impl.AesGcmEncryptionService;
import com.securechat.common.crypto.impl.HkdfKeyDerivationService;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.dto.EncryptedMessageDto;
import com.securechat.common.dto.KeyExchangeBundleDto;
import com.securechat.common.dto.SendMessageRequest;
import com.securechat.common.exception.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/**
 * Client-side Post-Quantum Session State Machine implementing the PQ-X3DH protocol:
 * - Session initiation with ML-KEM-768 key encapsulation against signed prekey and one-time prekey
 * - Session key derivation via RFC 5869 HKDF-SHA256
 * - Symmetric message encryption via AES-256-GCM
 * - Sender message authentication via ML-DSA-65 digital signatures
 */
public class PqSessionManager {

    private static final Logger log = LoggerFactory.getLogger(PqSessionManager.class);
    private static final byte[] PROTOCOL_SALT = "LatticeChat-PQ-X3DH-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INFO_SESSION_KEY = "session-key".getBytes(StandardCharsets.UTF_8);

    private final String currentUsername;
    private final ClientKeystore keystore;
    private final LocalStorageService storage;

    private final KeyExchangeService kemService;
    private final SignatureService dsaService;
    private final EncryptionService encryptionService;
    private final KeyDerivationService hkdfService;

    public PqSessionManager(String currentUsername, ClientKeystore keystore, LocalStorageService storage) {
        this.currentUsername = currentUsername;
        this.keystore = keystore;
        this.storage = storage;

        this.kemService = new MlKemKeyExchangeService();
        this.dsaService = new MlDsaSignatureService();
        this.encryptionService = new AesGcmEncryptionService();
        this.hkdfService = new HkdfKeyDerivationService();
    }

    /**
     * Checks whether an established post-quantum session exists with the peer.
     */
    public boolean hasActiveSession(String peerUsername) throws SQLException {
        return storage.hasSession(peerUsername);
    }

    /**
     * Initiates a new PQ-X3DH session with a peer using their fetched public key bundle.
     * Returns the serialized encapsulation ciphertext to attach to the initial message.
     */
    public String initiateSession(String peerUsername, KeyExchangeBundleDto bundle) throws Exception {
        log.info("Initiating PQ-X3DH session with peer '{}'", peerUsername);

        byte[] peerIdKey = Base64.getDecoder().decode(bundle.identityKey());
        byte[] peerSpk = Base64.getDecoder().decode(bundle.signedPrekey());
        byte[] spkSig = Base64.getDecoder().decode(bundle.signedPrekeySignature());

        // 1. Verify peer's signed prekey signature
        boolean spkValid = dsaService.verify(peerSpk, spkSig, peerIdKey);
        if (!spkValid) {
            throw new CryptoException("Peer's signed prekey signature verification failed! Possible MitM attack.");
        }

        // 2. Encapsulate against peer's signed prekey
        KemSecret spkSecret = kemService.encapsulate(peerSpk);
        byte[] ssSpk = spkSecret.sharedSecret();
        byte[] ctSpk = spkSecret.encapsulationCiphertext();

        byte[] ikm;
        String encapsulationHeader;

        // 3. Encapsulate against optional one-time prekey
        if (bundle.oneTimePrekey() != null && bundle.oneTimePrekeyId() != null) {
            byte[] peerOpk = Base64.getDecoder().decode(bundle.oneTimePrekey());
            KemSecret opkSecret = kemService.encapsulate(peerOpk);
            byte[] ssOpk = opkSecret.sharedSecret();
            byte[] ctOpk = opkSecret.encapsulationCiphertext();

            ikm = concat(ssSpk, ssOpk);
            encapsulationHeader = bundle.oneTimePrekeyId() + ":" +
                    Base64.getEncoder().encodeToString(ctSpk) + ":" +
                    Base64.getEncoder().encodeToString(ctOpk);
        } else {
            ikm = ssSpk;
            encapsulationHeader = Base64.getEncoder().encodeToString(ctSpk);
        }

        // 4. Derive symmetric 256-bit session key
        byte[] sessionKey = hkdfService.deriveKey(ikm, PROTOCOL_SALT, INFO_SESSION_KEY, 32);

        // 5. Store session key in SQLite with bundle key version
        int keyVersion = bundle.keyVersion() > 0 ? bundle.keyVersion() : 1;
        storage.saveSession(peerUsername, Base64.getEncoder().encodeToString(sessionKey), bundle.identityKey(), keyVersion);

        return encapsulationHeader;
    }

    /**
     * Re-negotiates an active PQ-X3DH session with a peer using an updated public key bundle (e.g. after peer key rotation).
     * Replaces the local session key with the newly derived secret bound to the new key version.
     */
    public String renegotiateSession(String peerUsername, KeyExchangeBundleDto newBundle) throws Exception {
        log.info("Re-negotiating PQ-X3DH session with peer '{}' for key version v{}", peerUsername, newBundle.keyVersion());
        storage.invalidateSession(peerUsername);
        return initiateSession(peerUsername, newBundle);
    }

    /**
     * Invalidates the local session key for the specified peer, forcing a fresh key exchange handshake.
     */
    public void invalidateSession(String peerUsername) throws SQLException {
        log.info("Invalidating local session for peer '{}'", peerUsername);
        storage.invalidateSession(peerUsername);
    }

    /**
     * Clears all local sessions, e.g. when local keys are revoked or rotated.
     */
    public void clearAllSessions() throws SQLException {
        log.info("Clearing all established peer sessions");
        storage.clearAllSessions();
    }

    /**
     * Checks the recorded key version for an established peer session.
     */
    public int getPeerKeyVersion(String peerUsername) throws SQLException {
        return storage.getPeerKeyVersion(peerUsername).orElse(1);
    }

    /**
     * Encrypts and digitally signs an outgoing message for transmission to the recipient.
     */
    public SendMessageRequest prepareOutgoingMessage(String recipientUsername,
                                                    String plaintext,
                                                    String ephemeralKemCiphertext,
                                                    long sequenceNumber) throws Exception {
        String sessionKeyB64 = storage.getSessionKey(recipientUsername)
                .orElseThrow(() -> new IllegalStateException("No active session with peer '" + recipientUsername + "'"));

        byte[] sessionKey = Base64.getDecoder().decode(sessionKeyB64);
        String messageId = UUID.randomUUID().toString();

        // 1. Encrypt plaintext with AES-256-GCM
        byte[] encryptedPackage = encryptionService.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), sessionKey, null);
        byte[] iv = Arrays.copyOfRange(encryptedPackage, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(encryptedPackage, 12, encryptedPackage.length);

        String nonceB64 = Base64.getEncoder().encodeToString(iv);
        String ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);

        // 2. Sign payload with sender's ML-DSA-65 identity key
        String payloadToSign = buildPayloadString(messageId, sequenceNumber, nonceB64, ciphertextB64);
        byte[] signature = dsaService.sign(payloadToSign.getBytes(StandardCharsets.UTF_8), keystore.getIdentityKey().privateKey());
        String signatureB64 = Base64.getEncoder().encodeToString(signature);

        // 3. Cache outgoing message in local SQLite
        LocalMessage localMsg = new LocalMessage(
                null,
                messageId,
                recipientUsername,
                "OUTGOING",
                plaintext,
                "SENT",
                sequenceNumber,
                Instant.now()
        );
        storage.saveMessage(localMsg);

        return new SendMessageRequest(
                recipientUsername,
                messageId,
                ciphertextB64,
                nonceB64,
                ephemeralKemCiphertext,
                signatureB64,
                sequenceNumber
        );
    }

    /**
     * Decrypts an incoming message from a peer, establishing the session if initial handshake,
     * verifying sender's ML-DSA signature, and saving to local SQLite.
     */
    public LocalMessage processIncomingMessage(EncryptedMessageDto incoming, String senderIdentityKeyB64) throws Exception {
        String sender = incoming.senderUsername();

        // 1. Establish or update session if not yet present or if re-negotiation encapsulation is provided
        boolean hasEncapsulation = incoming.encapsulationCiphertextBase64() != null && !incoming.encapsulationCiphertextBase64().isBlank();
        if (!storage.hasSession(sender) || hasEncapsulation) {
            if (!hasEncapsulation) {
                throw new IllegalStateException("No active session for peer '" + sender + "' and no KEM encapsulation provided");
            }
            receiveSession(sender, senderIdentityKeyB64, incoming.encapsulationCiphertextBase64());
        }

        String sessionKeyB64 = storage.getSessionKey(sender)
                .orElseThrow(() -> new IllegalStateException("Failed to retrieve established session key for '" + sender + "'"));
        byte[] sessionKey = Base64.getDecoder().decode(sessionKeyB64);

        // 2. Verify sender's ML-DSA-65 signature
        String storedPeerIdKeyB64 = storage.getPeerIdentityKey(sender).orElse(senderIdentityKeyB64);
        if (storedPeerIdKeyB64 == null) {
            throw new IllegalStateException("Cannot verify message: sender identity key unknown");
        }
        byte[] peerIdKey = Base64.getDecoder().decode(storedPeerIdKeyB64);

        String payloadToVerify = buildPayloadString(
                incoming.messageId(),
                incoming.sequenceNumber(),
                incoming.nonceBase64(),
                incoming.ciphertextBase64()
        );

        byte[] sigBytes = Base64.getDecoder().decode(incoming.signatureBase64());
        boolean sigValid = dsaService.verify(payloadToVerify.getBytes(StandardCharsets.UTF_8), sigBytes, peerIdKey);
        if (!sigValid) {
            throw new CryptoException("Message signature verification failed for incoming message [" + incoming.messageId() + "]");
        }

        // 3. Decrypt ciphertext with AES-256-GCM
        byte[] iv = Base64.getDecoder().decode(incoming.nonceBase64());
        byte[] ciphertextWithTag = Base64.getDecoder().decode(incoming.ciphertextBase64());

        byte[] encryptedPackage = new byte[iv.length + ciphertextWithTag.length];
        System.arraycopy(iv, 0, encryptedPackage, 0, iv.length);
        System.arraycopy(ciphertextWithTag, 0, encryptedPackage, iv.length, ciphertextWithTag.length);

        byte[] plaintextBytes = encryptionService.decrypt(encryptedPackage, sessionKey, null);
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);

        // 4. Save to local SQLite
        LocalMessage localMsg = new LocalMessage(
                null,
                incoming.messageId(),
                sender,
                "INCOMING",
                plaintext,
                incoming.status(),
                incoming.sequenceNumber(),
                incoming.sentAt() != null ? incoming.sentAt() : Instant.now()
        );
        storage.saveMessage(localMsg);

        return localMsg;
    }

    private void receiveSession(String peerUsername, String peerIdentityKeyB64, String encapsulationHeader) throws Exception {
        log.info("Receiving new PQ-X3DH session from peer '{}'", peerUsername);

        byte[] ikm;
        if (encapsulationHeader.contains(":")) {
            String[] parts = encapsulationHeader.split(":");
            long opkId = Long.parseLong(parts[0]);
            byte[] ctSpk = Base64.getDecoder().decode(parts[1]);
            byte[] ctOpk = Base64.getDecoder().decode(parts[2]);

            // Decapsulate against signed prekey
            byte[] ssSpk = kemService.decapsulate(keystore.getSignedPrekey().privateKey(), ctSpk);

            // Decapsulate against one-time prekey
            KemKeyPair opkPair = keystore.consumeOneTimePrekey(opkId);
            if (opkPair == null) {
                throw new IllegalStateException("One-time prekey ID " + opkId + " was not found in keystore");
            }
            byte[] ssOpk = kemService.decapsulate(opkPair.privateKey(), ctOpk);

            ikm = concat(ssSpk, ssOpk);
        } else {
            byte[] ctSpk = Base64.getDecoder().decode(encapsulationHeader);
            byte[] ssSpk = kemService.decapsulate(keystore.getSignedPrekey().privateKey(), ctSpk);
            ikm = ssSpk;
        }

        byte[] sessionKey = hkdfService.deriveKey(ikm, PROTOCOL_SALT, INFO_SESSION_KEY, 32);
        storage.saveSession(peerUsername, Base64.getEncoder().encodeToString(sessionKey), peerIdentityKeyB64);
    }

    public static String buildPayloadString(String messageId, long seq, String nonce, String ciphertext) {
        return messageId + ":" + seq + ":" + nonce + ":" + ciphertext;
    }

    /**
     * Calculates the SHA-256 fingerprint of a public key formatted in readable hex chunks.
     */
    public static String computeKeyFingerprint(String base64PublicKey) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest(keyBytes);

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                sb.append(String.format("%02X", digest[i]));
                if ((i + 1) % 4 == 0 && i < digest.length - 1) {
                    sb.append(" ");
                }
            }
            return sb.toString();
        } catch (Exception e) {
            return "N/A";
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
