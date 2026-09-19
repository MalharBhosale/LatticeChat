package com.securechat.client.controller;

import com.securechat.client.context.ClientContext;
import com.securechat.client.protocol.PqSessionManager;
import com.securechat.common.dto.AuditLogDto;
import com.securechat.common.dto.KeyExchangeBundleDto;
import com.securechat.common.dto.RevokeKeyBundleRequest;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Controller for the Cryptographic Verification, Key Lifecycle, and Safety Number Dialog.
 * Enables:
 * 1. Out-of-band visual verification of post-quantum key fingerprints & 12-digit safety numbers.
 * 2. On-demand signed prekey rotation (v1 -> v2...).
 * 3. Ephemeral PQ-X3DH session re-negotiation.
 * 4. Explicit key bundle revocation & invalidation.
 * 5. Real-time cryptographic audit trail inspection.
 */
public class SecurityInfoController {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss dd-MMM").withZone(ZoneId.systemDefault());

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

    @FXML
    private Label keyVersionLabel;

    @FXML
    private Label rotationStatusLabel;

    @FXML
    private Button btnRotatePrekey;

    @FXML
    private Button btnRenegotiateSession;

    @FXML
    private Button btnRevokeKey;

    @FXML
    private VBox auditLogsContainer;

    private String currentPeer;

    public void initData(String peerUsername) {
        this.currentPeer = peerUsername;
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

        int localVer = 1;
        try {
            localVer = ctx.getSessionManager().getPeerKeyVersion(peerUsername);
        } catch (Exception ignored) {}

        if (keyVersionLabel != null) {
            keyVersionLabel.setText("Peer Session Bundle: v" + localVer);
        }

        loadAuditTrail();
    }

    @FXML
    private void handleRotatePrekey(ActionEvent event) {
        btnRotatePrekey.setDisable(true);
        if (rotationStatusLabel != null) {
            rotationStatusLabel.setText("Generating fresh ML-KEM-768 prekey & signing with ML-DSA-65...");
            rotationStatusLabel.setStyle("-fx-text-fill: #38bdf8;");
        }

        CompletableFuture.runAsync(() -> {
            try {
                ClientContext ctx = ClientContext.getInstance();
                var keystore = ctx.getKeystore();

                // 1. Rotate in keystore (fresh ML-KEM-768 prekey + signature)
                var newSpk = keystore.rotateSignedPrekey();
                String prekeyB64 = Base64.getEncoder().encodeToString(newSpk.publicKey());
                String sigB64 = Base64.getEncoder().encodeToString(keystore.getSignedPrekeySignature());

                // 2. Upload to server
                com.securechat.common.dto.RotateKeyBundleRequest req =
                        new com.securechat.common.dto.RotateKeyBundleRequest(prekeyB64, "ML-KEM-768", sigB64, null);

                var response = ctx.getApiClient().rotateKeyBundle(req);

                Platform.runLater(() -> {
                    btnRotatePrekey.setDisable(false);
                    if (keyVersionLabel != null) {
                        keyVersionLabel.setText("Active Key Version: v" + response.keyVersion() + " (Rotated)");
                    }
                    if (rotationStatusLabel != null) {
                        rotationStatusLabel.setText("✓ Prekey rotated to v" + response.keyVersion() + "! Server audit logged.");
                        rotationStatusLabel.setStyle("-fx-text-fill: #10b981; -fx-font-weight: bold;");
                    }
                    loadAuditTrail();
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    btnRotatePrekey.setDisable(false);
                    if (rotationStatusLabel != null) {
                        rotationStatusLabel.setText("Rotation failed: " + e.getMessage());
                        rotationStatusLabel.setStyle("-fx-text-fill: #ef4444;");
                    }
                });
            }
        });
    }

    @FXML
    private void handleRenegotiateSession(ActionEvent event) {
        if (currentPeer == null || currentPeer.isBlank()) return;

        btnRenegotiateSession.setDisable(true);
        if (rotationStatusLabel != null) {
            rotationStatusLabel.setText("Re-negotiating PQ-X3DH session with @" + currentPeer + "...");
            rotationStatusLabel.setStyle("-fx-text-fill: #38bdf8;");
        }

        CompletableFuture.runAsync(() -> {
            try {
                ClientContext ctx = ClientContext.getInstance();
                KeyExchangeBundleDto newBundle = ctx.getApiClient().getKeyBundle(currentPeer);
                ctx.getSessionManager().renegotiateSession(currentPeer, newBundle);

                Platform.runLater(() -> {
                    btnRenegotiateSession.setDisable(false);
                    if (keyVersionLabel != null) {
                        keyVersionLabel.setText("Peer Session Bundle: v" + newBundle.keyVersion() + " (Re-negotiated)");
                    }
                    if (rotationStatusLabel != null) {
                        rotationStatusLabel.setText("✓ Session re-negotiated with @" + currentPeer + " (v" + newBundle.keyVersion() + ")!");
                        rotationStatusLabel.setStyle("-fx-text-fill: #10b981; -fx-font-weight: bold;");
                    }
                    loadAuditTrail();
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    btnRenegotiateSession.setDisable(false);
                    if (rotationStatusLabel != null) {
                        rotationStatusLabel.setText("Re-negotiation failed: " + e.getMessage());
                        rotationStatusLabel.setStyle("-fx-text-fill: #ef4444;");
                    }
                });
            }
        });
    }

    @FXML
    private void handleRevokeKey(ActionEvent event) {
        btnRevokeKey.setDisable(true);
        if (rotationStatusLabel != null) {
            rotationStatusLabel.setText("Revoking active key bundle on server...");
            rotationStatusLabel.setStyle("-fx-text-fill: #f59e0b;");
        }

        CompletableFuture.runAsync(() -> {
            try {
                ClientContext ctx = ClientContext.getInstance();
                ctx.getApiClient().revokeKeyBundle(new RevokeKeyBundleRequest("USER_INITIATED_REVOCATION", "Revoked via Security Dashboard"));
                ctx.getSessionManager().clearAllSessions();

                Platform.runLater(() -> {
                    btnRevokeKey.setDisable(false);
                    if (keyVersionLabel != null) {
                        keyVersionLabel.setText("Active Key Version: REVOKED");
                    }
                    if (rotationStatusLabel != null) {
                        rotationStatusLabel.setText("⚠️ Key bundle revoked! All active peer sessions cleared.");
                        rotationStatusLabel.setStyle("-fx-text-fill: #ef4444; -fx-font-weight: bold;");
                    }
                    loadAuditTrail();
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    btnRevokeKey.setDisable(false);
                    if (rotationStatusLabel != null) {
                        rotationStatusLabel.setText("Revocation failed: " + e.getMessage());
                        rotationStatusLabel.setStyle("-fx-text-fill: #ef4444;");
                    }
                });
            }
        });
    }

    @FXML
    private void handleRefreshAuditTrail(ActionEvent event) {
        loadAuditTrail();
    }

    private void loadAuditTrail() {
        if (auditLogsContainer == null) return;

        CompletableFuture.runAsync(() -> {
            try {
                ClientContext ctx = ClientContext.getInstance();
                List<AuditLogDto> trail = ctx.getApiClient().getAuditTrail();

                Platform.runLater(() -> {
                    auditLogsContainer.getChildren().clear();
                    if (trail.isEmpty()) {
                        Label emptyLbl = new Label("No audit events recorded yet.");
                        emptyLbl.getStyleClass().add("card-hint");
                        auditLogsContainer.getChildren().add(emptyLbl);
                        return;
                    }

                    for (AuditLogDto entry : trail.stream().limit(6).toList()) {
                        VBox entryBox = new VBox(2);
                        entryBox.getStyleClass().add("audit-entry");

                        HBox header = new HBox(8);
                        header.setAlignment(Pos.CENTER_LEFT);

                        Label badge = new Label(entry.eventType());
                        badge.getStyleClass().add("audit-badge");

                        String timeStr = entry.createdAt() != null ? TIME_FMT.format(entry.createdAt()) : "Just now";
                        Label timeLbl = new Label(timeStr);
                        timeLbl.getStyleClass().add("card-hint");

                        header.getChildren().addAll(badge, timeLbl);

                        Label detailLbl = new Label(entry.details());
                        detailLbl.setStyle("-fx-font-size: 11px; -fx-text-fill: #cbd5e1;");
                        detailLbl.setWrapText(true);

                        entryBox.getChildren().addAll(header, detailLbl);
                        auditLogsContainer.getChildren().add(entryBox);
                    }
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    auditLogsContainer.getChildren().clear();
                    Label errLbl = new Label("Could not fetch audit trail: " + e.getMessage());
                    errLbl.setStyle("-fx-text-fill: #ef4444; -fx-font-size: 11px;");
                    auditLogsContainer.getChildren().add(errLbl);
                });
            }
        });
    }

    private String computeSafetyNumber(String k1, String k2) {
        try {
            String combined = k1.compareTo(k2) < 0 ? k1 + k2 : k2 + k1;
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha.digest(combined.getBytes(StandardCharsets.UTF_8));

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
