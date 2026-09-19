package com.securechat.client.controller;

import com.securechat.client.context.ClientContext;
import com.securechat.client.protocol.PqSessionManager;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.stage.Stage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Controller for the Cryptographic Verification & Safety Number Dialog.
 * Enables out-of-band visual verification of post-quantum key fingerprints.
 */
public class SecurityInfoController {

    @FXML
    private Label peerNameLabel;

    @FXML
    private Label peerFingerprintLabel;

    @FXML
    private Label localFingerprintLabel;

    @FXML
    private Label safetyNumberLabel;

    @FXML
    private Label algorithmsLabel;

    public void initData(String peerUsername) {
        peerNameLabel.setText("@" + peerUsername);

        ClientContext ctx = ClientContext.getInstance();
        String localIdKeyB64 = Base64.getEncoder().encodeToString(ctx.getKeystore().getIdentityKey().publicKey());
        String localFp = PqSessionManager.computeKeyFingerprint(localIdKeyB64);
        localFingerprintLabel.setText(localFp);

        String peerIdKeyB64 = null;
        try {
            peerIdKeyB64 = ctx.getStorage().getPeerIdentityKey(peerUsername).orElse(null);
        } catch (Exception ignored) {}

        String peerFp = peerIdKeyB64 != null ? PqSessionManager.computeKeyFingerprint(peerIdKeyB64) : "Bundle Not Yet Loaded";
        peerFingerprintLabel.setText(peerFp);

        // Compute 12-digit safety number: SHA-256(min(local, peer) || max(local, peer))
        if (peerIdKeyB64 != null) {
            String safety = computeSafetyNumber(localIdKeyB64, peerIdKeyB64);
            safetyNumberLabel.setText(safety);
        } else {
            safetyNumberLabel.setText("---- ---- ----");
        }

        algorithmsLabel.setText(
                "• Key Encapsulation: NIST FIPS 203 ML-KEM-768 (Lattice Kyber)\n" +
                "• Digital Signatures: NIST FIPS 204 ML-DSA-65 (Lattice Dilithium)\n" +
                "• Symmetric Cipher: AES-256-GCM (NIST SP 800-38D, 128-bit tag)\n" +
                "• Key Derivation: RFC 5869 HKDF-SHA256"
        );
    }

    private String computeSafetyNumber(String k1, String k2) {
        try {
            String combined = k1.compareTo(k2) < 0 ? k1 + k2 : k2 + k1;
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha.digest(combined.getBytes(StandardCharsets.UTF_8));

            // Format first 6 bytes as two 6-digit blocks
            long num1 = ((hash[0] & 0xFFL) << 16) | ((hash[1] & 0xFFL) << 8) | (hash[2] & 0xFFL);
            long num2 = ((hash[3] & 0xFFL) << 16) | ((hash[4] & 0xFFL) << 8) | (hash[5] & 0xFFL);

            return String.format("%06d %06d", num1 % 1000000L, num2 % 1000000L);
        } catch (Exception e) {
            return "000000 000000";
        }
    }

    @FXML
    private void handleClose(ActionEvent event) {
        Stage stage = (Stage) peerNameLabel.getScene().getWindow();
        stage.close();
    }
}
