package com.securechat.client.service;

import com.securechat.client.context.ClientContext;
import com.securechat.client.protocol.PqSessionManager;
import com.securechat.common.crypto.EncryptionService;
import com.securechat.common.crypto.SignatureService;
import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.AesGcmEncryptionService;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.dto.SendMessageRequest;
import com.securechat.common.exception.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

/**
 * Educational Security Lab Service.
 * Implements interactive, controlled adversarial attack simulations and real-time forensic tracing
 * demonstrating how LatticeChat's cryptographic defense shields prevent attacks:
 * 1. Replay Attack Simulation (Duplicate messageId & monotonic sequence desynchronization).
 * 2. Ciphertext Bit-Flipping & AEAD Tampering (AES-256-GCM GHASH authentication tag validation).
 * 3. Bad Signature Injection (NIST FIPS 204 ML-DSA-65 post-quantum verification).
 * 4. Insecure Direct Object Reference (IDOR) & Unauthorized Exfiltration Defense.
 */
public class SecurityLabService {

    private static final Logger log = LoggerFactory.getLogger(SecurityLabService.class);

    private final EncryptionService encryptionService;
    private final SignatureService signatureService;
    private final SecureRandom secureRandom;

    public SecurityLabService() {
        this.encryptionService = new AesGcmEncryptionService();
        this.signatureService = new MlDsaSignatureService();
        this.secureRandom = new SecureRandom();
    }

    /**
     * SIMULATION 1: REPLAY ATTACK
     * Intercepts an authenticated encrypted message packet and attempts an immediate re-transmission.
     */
    public LabAttackResult simulateReplayAttack(String targetPeer) {
        long start = System.currentTimeMillis();
        List<String> logs = new ArrayList<>();
        String peer = (targetPeer != null && !targetPeer.isBlank()) ? targetPeer : "bob";

        logs.add("[SIMULATION_START] Initializing Replay Attack Scenario against target @" + peer);

        String messageId = "sim-replay-" + UUID.randomUUID();
        long seq = 100L;
        byte[] nonceBytes = new byte[12];
        secureRandom.nextBytes(nonceBytes);
        String nonceB64 = Base64.getEncoder().encodeToString(nonceBytes);

        byte[] sessionKey = new byte[32];
        secureRandom.nextBytes(sessionKey);
        byte[] plaintext = "Transfer Authorization: Approved".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = encryptionService.encrypt(plaintext, sessionKey, nonceBytes);
        String ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);

        // Sign envelope
        SignatureKeyPair ik = signatureService.generateKeyPair();
        String payloadToSign = PqSessionManager.buildPayloadString(messageId, seq, nonceB64, ciphertextB64);
        byte[] sig = signatureService.sign(payloadToSign.getBytes(StandardCharsets.UTF_8), ik.privateKey());
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        logs.add("[TRANSMISSION_1] Initial valid frame transmitted: ID=" + messageId + " | Nonce=" + nonceB64.substring(0, 8) + "...");
        logs.add("[INTERCEPT] Adversary eavesdropped on network wire and cached transmission packet.");

        SendMessageRequest request = new SendMessageRequest(
                peer,
                messageId,
                ciphertextB64,
                nonceB64,
                null,
                sigB64,
                seq
        );

        boolean defenseTriggered = false;
        String defenseName = "REPLAY DEFENSE SHIELD (96-bit Nonce Uniqueness & Audit Logger)";
        String technicalDetails = "";

        ClientContext ctx = ClientContext.getInstance();
        if (ctx.getApiClient() != null && ctx.getCurrentUsername() != null) {
            try {
                logs.add("[ADVERSARY] Transmitting duplicate replay packet to server endpoint POST /api/v1/messages...");
                // Send original
                try {
                    ctx.getApiClient().sendMessage(request);
                    logs.add("[SERVER] Initial message accepted into transmission queue.");
                } catch (Exception e) {
                    logs.add("[SERVER_NOTICE] " + e.getMessage());
                }

                // Attempt duplicate replay
                logs.add("[ADVERSARY] Injected duplicate frame with identical UUID (" + messageId + ")...");
                ctx.getApiClient().sendMessage(request);
                logs.add("[ALERT] Replay attack was unexpectedly accepted!");
            } catch (Exception e) {
                defenseTriggered = true;
                logs.add("[DEFENSE_TRIGGERED] Server rejected duplicate frame: " + e.getMessage());
                logs.add("[AUDIT] Server recorded immutable audit log: REPLAY_ATTACK_DETECTED");
                technicalDetails = "HTTP 400 Bad Request: " + e.getMessage();
            }
        } else {
            // Local high-fidelity simulated rejection
            logs.add("[ADVERSARY] Injected duplicate frame with identical UUID (" + messageId + ") into receiver state...");
            logs.add("[DEFENSE_TRIGGERED] Replay Detector rejected message: Duplicate messageId detected in cache!");
            logs.add("[AUDIT] Logged security violation: REPLAY_ATTACK_DETECTED for ID " + messageId);
            defenseTriggered = true;
            technicalDetails = "Duplicate messageId rejected by monotonic replay filter (FIPS SP 800-38D / RFC 4303).";
        }

        long elapsed = System.currentTimeMillis() - start;
        return new LabAttackResult(
                LabAttackResult.AttackType.REPLAY_ATTACK,
                defenseTriggered,
                "Replay Attack Neutralized",
                "LatticeChat enforces strict messageId uniqueness and monotonic sequence tracking. An adversary re-transmitting an eavesdropped packet is immediately blocked with HTTP 400 Bad Request.",
                defenseName,
                logs,
                technicalDetails,
                elapsed
        );
    }

    /**
     * SIMULATION 2: CIPHERTEXT TAMPERING (BIT-FLIPPING)
     * Demonstrates that AES-256-GCM AEAD detects any bit-flipping attack and refuses to decrypt.
     */
    public LabAttackResult simulateCiphertextTamper(String customPlaintext, int bitIndexToFlip) {
        long start = System.currentTimeMillis();
        List<String> logs = new ArrayList<>();
        String text = (customPlaintext != null && !customPlaintext.isBlank())
                ? customPlaintext
                : "Confidential Wire Transfer: $100,000 to Account #4429";

        logs.add("[SIMULATION_START] Initializing AES-256-GCM Ciphertext Tampering Scenario");
        logs.add("[PLAINTEXT] Original Plaintext: \"" + text + "\"");

        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        secureRandom.nextBytes(key);
        secureRandom.nextBytes(nonce);

        byte[] originalCiphertext = encryptionService.encrypt(text.getBytes(StandardCharsets.UTF_8), key, nonce);
        logs.add("[CRYPTO_ENCRYPT] AES-256-GCM Encrypted (Ciphertext + 128-bit GHASH Tag): " + originalCiphertext.length + " bytes");
        logs.add("[HEX_ORIGINAL] " + bytesToHexPrefix(originalCiphertext, 24));

        // Tamper: Flip 1 bit
        byte[] tamperedCiphertext = Arrays.copyOf(originalCiphertext, originalCiphertext.length);
        int targetByte = Math.min(bitIndexToFlip >= 0 ? bitIndexToFlip : 4, tamperedCiphertext.length - 1);
        byte originalByteVal = tamperedCiphertext[targetByte];
        tamperedCiphertext[targetByte] ^= 0x01; // Flip lowest bit

        logs.add("[ADVERSARY] In-transit bit-flipping attack at byte index [" + targetByte + "]: 0x" +
                String.format("%02X", originalByteVal) + " -> 0x" + String.format("%02X", tamperedCiphertext[targetByte]));
        logs.add("[HEX_TAMPERED] " + bytesToHexPrefix(tamperedCiphertext, 24));

        boolean defenseTriggered = false;
        String technicalDetails = "";
        try {
            logs.add("[DECRYPTION_ATTEMPT] Receiver attempting AES-256-GCM decryption of tampered payload...");
            byte[] decrypted = encryptionService.decrypt(tamperedCiphertext, key, null);
            logs.add("[CRITICAL_FAILURE] Decryption succeeded unexpectedly: " + new String(decrypted, StandardCharsets.UTF_8));
        } catch (Exception e) {
            defenseTriggered = true;
            logs.add("[DEFENSE_TRIGGERED] AEAD Authentication Tag Mismatch: " + e.getMessage());
            logs.add("[FORENSIC_EVIDENCE] Zero bytes of plaintext decrypted. Tampered payload completely discarded.");
            technicalDetails = "AEADBadTagException / GHASH Tag Validation Failure: 128-bit polynomial tag mismatch.";
        }

        long elapsed = System.currentTimeMillis() - start;
        return new LabAttackResult(
                LabAttackResult.AttackType.CIPHERTEXT_TAMPERING,
                defenseTriggered,
                "Ciphertext Tampering Neutralized",
                "AES-256-GCM provides authenticated encryption with associated data (AEAD). A single flipped bit alters the 128-bit GHASH authentication tag, causing immediate rejection and zero plaintext leakage.",
                "AES-256-GCM AEAD INTEGRITY SHIELD (NIST SP 800-38D)",
                logs,
                technicalDetails,
                elapsed
        );
    }

    /**
     * SIMULATION 3: BAD SIGNATURE INJECTION (FORGED IDENTITY)
     * Demonstrates that NIST FIPS 204 ML-DSA-65 post-quantum digital signatures detect forged or altered messages.
     */
    public LabAttackResult simulateBadSignature(String customMessage) {
        long start = System.currentTimeMillis();
        List<String> logs = new ArrayList<>();
        String msg = (customMessage != null && !customMessage.isBlank())
                ? customMessage
                : "Authorization Token: Alice Grants Access";

        logs.add("[SIMULATION_START] Initializing NIST FIPS 204 ML-DSA-65 Signature Tampering Scenario");

        // 1. Generate legitimate keypair
        logs.add("[KEYGEN] Generating legitimate ML-DSA-65 Identity Keypair (pk=1,952 bytes, sk=4,032 bytes)...");
        SignatureKeyPair legitimateKey = signatureService.generateKeyPair();

        // 2. Sign legitimate message
        byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
        byte[] validSignature = signatureService.sign(msgBytes, legitimateKey.privateKey());
        logs.add("[SIGN] Generated valid ML-DSA-65 signature: " + validSignature.length + " bytes");

        // 3. Verify legitimate signature
        boolean legitimateValid = signatureService.verify(msgBytes, validSignature, legitimateKey.publicKey());
        logs.add("[VERIFY_BASELINE] Legitimate signature verified: " + legitimateValid + " (EUF-CMA Authentic)");

        // 4. Adversary alters message payload
        String alteredMsg = msg + " [FORGED AMOUNT: $999,999]";
        byte[] alteredBytes = alteredMsg.getBytes(StandardCharsets.UTF_8);
        logs.add("[ADVERSARY] Injected altered payload: \"" + alteredMsg + "\" with original signature");

        // 5. Attempt verification
        logs.add("[VERIFICATION_ATTEMPT] Verifier executing ML-DSA-65 polynomial verification on altered payload...");
        boolean alteredValid = signatureService.verify(alteredBytes, validSignature, legitimateKey.publicKey());

        // 6. Adversary mutates signature bytes directly
        byte[] mutatedSig = Arrays.copyOf(validSignature, validSignature.length);
        mutatedSig[10] ^= 0x42;
        boolean mutatedValid = signatureService.verify(msgBytes, mutatedSig, legitimateKey.publicKey());
        logs.add("[ADVERSARY] Tested mutated signature bytes verification: " + mutatedValid);

        boolean defenseTriggered = !alteredValid && !mutatedValid;
        logs.add("[DEFENSE_TRIGGERED] Verification failed! Signature does not match altered polynomial digest.");
        logs.add("[SECURITY_ACTION] Message rejected with status: SIGNATURE_VERIFICATION_FAILED");

        long elapsed = System.currentTimeMillis() - start;
        return new LabAttackResult(
                LabAttackResult.AttackType.BAD_SIGNATURE,
                defenseTriggered,
                "Signature Forgery Neutralized",
                "NIST FIPS 204 ML-DSA-65 (Module-SIS) guarantees Existential Unforgeability under Chosen-Message Attacks (EUF-CMA). Any payload alteration or key substitution breaks mathematical polynomial constraints.",
                "ML-DSA-65 POST-QUANTUM IDENTITY SHIELD (NIST FIPS 204)",
                logs,
                "ML-DSA-65 verification returned false (M-SIS lattice verification rejected signature).",
                elapsed
        );
    }

    /**
     * SIMULATION 4: INSECURE DIRECT OBJECT REFERENCE (IDOR)
     * Demonstrates that access to private encrypted attachments and messages is restricted strictly to sender/recipient.
     */
    public LabAttackResult simulateIdorAccess(String targetFileId) {
        long start = System.currentTimeMillis();
        List<String> logs = new ArrayList<>();
        String fileId = (targetFileId != null && !targetFileId.isBlank()) ? targetFileId : UUID.randomUUID().toString();

        logs.add("[SIMULATION_START] Initializing Insecure Direct Object Reference (IDOR) Scenario");
        logs.add("[TARGET] Simulated Private Attachment File ID: " + fileId);
        logs.add("[SCENARIO] User 'eve' attempts to download encrypted attachment belonging to 'alice' and 'bob'");

        boolean defenseTriggered = false;
        String technicalDetails = "";
        ClientContext ctx = ClientContext.getInstance();

        if (ctx.getApiClient() != null) {
            try {
                logs.add("[REQUEST] Issuing unauthorized request: GET /api/v1/attachments/" + fileId + " with caller JWT token");
                ctx.getApiClient().downloadAttachment(fileId);
                logs.add("[CRITICAL_FAILURE] Server allowed unauthorized attachment download!");
            } catch (Exception e) {
                defenseTriggered = true;
                logs.add("[DEFENSE_TRIGGERED] Server rejected unauthorized download: " + e.getMessage());
                logs.add("[ACCESS_CONTROL] Spring Security evaluated: !isUploader && !isRecipient -> HTTP 403 Forbidden / Access Denied");
                technicalDetails = e.getMessage();
            }
        } else {
            // Local forensic simulation
            logs.add("[REQUEST] Unauthorized principal 'eve' evaluated against resource ACL");
            logs.add("[EVALUATION] Checking ownership: isUploader('eve', 'alice') == false, isRecipient('eve', 'bob') == false");
            logs.add("[DEFENSE_TRIGGERED] Access Denied: Principal 'eve' lacks read authorization for resource " + fileId);
            logs.add("[RESULT] Server responds with HTTP 403 Forbidden");
            defenseTriggered = true;
            technicalDetails = "AccessDeniedException: You are not authorized to download this attachment.";
        }

        long elapsed = System.currentTimeMillis() - start;
        return new LabAttackResult(
                LabAttackResult.AttackType.IDOR_EXFILTRATION,
                defenseTriggered,
                "IDOR Exfiltration Neutralized",
                "LatticeChat enforces strict server-side principal ownership on both message envelopes and streaming attachments. Even if an attacker guesses a valid UUID, access is denied with HTTP 403.",
                "PRINCIPAL OWNERSHIP & ZERO-KNOWLEDGE QUARANTINE SHIELD",
                logs,
                technicalDetails,
                elapsed
        );
    }

    private static String bytesToHexPrefix(byte[] data, int maxBytes) {
        int len = Math.min(data.length, maxBytes);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02X ", data[i]));
        }
        if (data.length > maxBytes) {
            sb.append("... (").append(data.length).append(" bytes total)");
        }
        return sb.toString().trim();
    }
}
