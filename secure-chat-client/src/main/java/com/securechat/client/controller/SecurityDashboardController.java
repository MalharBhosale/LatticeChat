package com.securechat.client.controller;

import com.securechat.client.context.ClientContext;
import com.securechat.client.crypto.ClientKeystore;
import com.securechat.client.protocol.PqSessionManager;
import com.securechat.common.crypto.KeyExchangeService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.dto.AuditLogDto;
import com.securechat.common.dto.OneTimePrekeyUploadDto;
import com.securechat.common.dto.RotateKeyBundleRequest;
import com.securechat.common.dto.UploadPrekeysRequest;
import com.securechat.common.crypto.benchmark.PqcBenchmarkRunner;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Controller for the Full-Featured Cryptographic Security Dashboard & Inspector.
 * Provides deep visibility into:
 * 1. Active PQ-X3DH session state, peer verification status, and 12-digit safety numbers.
 * 2. NIST FIPS 203/204 Post-Quantum Cryptographic parameters (ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF).
 * 3. Client Keystore telemetry & One-Time Prekey (OPK) pool health.
 * 4. Real-time server cryptographic audit event logs.
 * 5. Live hardware microbenchmark execution and report export.
 */
public class SecurityDashboardController {

    private static final Logger log = LoggerFactory.getLogger(SecurityDashboardController.class);

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss dd-MMM").withZone(ZoneId.systemDefault());

    @FXML
    private Label peerUsernameLabel;

    @FXML
    private Label verificationStatusBadge;

    @FXML
    private Button btnToggleVerification;

    @FXML
    private Label safetyNumberLabel;

    @FXML
    private Label sessionKeyVersionLabel;

    @FXML
    private Label sessionKeyFingerprintLabel;

    @FXML
    private Label peerIdentityFingerprintLabel;

    @FXML
    private Label localIdentityFingerprintLabel;

    @FXML
    private Label keystoreIdentityFingerprint;

    @FXML
    private Label keystoreSpkFingerprint;

    @FXML
    private Label availableOpkCountLabel;

    @FXML
    private Label consumedOpkCountLabel;

    @FXML
    private Label opkHealthLabel;

    @FXML
    private VBox auditLogsList;

    @FXML
    private Label benchmarkStatusLabel;

    @FXML
    private Button btnRunBenchmark;

    @FXML
    private Button btnCopyMarkdown;

    @FXML
    private Label handshakeLatencyBadge;

    @FXML
    private Label handshakeTotalLatencyLabel;

    @FXML
    private Label handshakeWireOverheadLabel;

    @FXML
    private TextArea benchmarkConsoleArea;

    private String lastBenchmarkMarkdown;
    private String currentPeer;

    /**
     * Initializes the dashboard telemetry for the currently selected peer or active session.
     */
    public void initData(String peerUsername) {
        this.currentPeer = peerUsername;
        ClientContext ctx = ClientContext.getInstance();

        // 1. Peer and Session Telemetry
        if (peerUsername == null || peerUsername.isBlank()) {
            peerUsernameLabel.setText("None Selected");
            btnToggleVerification.setDisable(true);
            verificationStatusBadge.setText("NO ACTIVE PEER");
            safetyNumberLabel.setText("---- ---- ----");
            sessionKeyFingerprintLabel.setText("N/A");
            peerIdentityFingerprintLabel.setText("N/A");
            sessionKeyVersionLabel.setText("N/A");
        } else {
            peerUsernameLabel.setText("@" + peerUsername);
            btnToggleVerification.setDisable(false);

            // Load verification status from persistent local storage
            boolean verified = false;
            try {
                verified = ctx.getStorage().isPeerVerified(peerUsername);
            } catch (Exception e) {
                log.warn("Failed to query peer verification status: {}", e.getMessage());
            }
            updateVerificationBadge(verified);

            // Local Identity Key Fingerprint
            String localIdKeyB64 = null;
            if (ctx.getKeystore() != null && ctx.getKeystore().getIdentityKey() != null) {
                localIdKeyB64 = Base64.getEncoder().encodeToString(ctx.getKeystore().getIdentityKey().publicKey());
                String localFp = PqSessionManager.computeKeyFingerprint(localIdKeyB64);
                localIdentityFingerprintLabel.setText(localFp);
            } else {
                localIdentityFingerprintLabel.setText("N/A");
            }

            // Peer Identity Key Fingerprint
            String peerIdKeyB64 = null;
            try {
                peerIdKeyB64 = ctx.getStorage().getPeerIdentityKey(peerUsername).orElse(null);
            } catch (Exception ignored) {}

            if (peerIdKeyB64 != null) {
                String peerFp = PqSessionManager.computeKeyFingerprint(peerIdKeyB64);
                peerIdentityFingerprintLabel.setText(peerFp);

                // Compute 12-digit safety number
                if (localIdKeyB64 != null) {
                    safetyNumberLabel.setText(computeSafetyNumber(localIdKeyB64, peerIdKeyB64));
                } else {
                    safetyNumberLabel.setText("---- ---- ----");
                }
            } else {
                peerIdentityFingerprintLabel.setText("Session Not Yet Initiated");
                safetyNumberLabel.setText("---- ---- ----");
            }

            // Session Key Fingerprint
            try {
                Optional<String> sessionKeyB64 = ctx.getStorage().getSessionKey(peerUsername);
                if (sessionKeyB64.isPresent()) {
                    sessionKeyFingerprintLabel.setText(PqSessionManager.computeKeyFingerprint(sessionKeyB64.get()));
                } else {
                    sessionKeyFingerprintLabel.setText("No Active Session");
                }
            } catch (Exception e) {
                sessionKeyFingerprintLabel.setText("Error Reading Session");
            }

            // Peer Key Version
            int version = 1;
            try {
                if (ctx.getSessionManager() != null) {
                    version = ctx.getSessionManager().getPeerKeyVersion(peerUsername);
                }
            } catch (Exception ignored) {}
            sessionKeyVersionLabel.setText("v" + version);
        }

        // 2. Keystore Telemetry
        if (ctx.getKeystore() != null) {
            if (ctx.getKeystore().getIdentityKey() != null) {
                String ikB64 = Base64.getEncoder().encodeToString(ctx.getKeystore().getIdentityKey().publicKey());
                keystoreIdentityFingerprint.setText(PqSessionManager.computeKeyFingerprint(ikB64));
            }
            if (ctx.getKeystore().getSignedPrekey() != null) {
                String spkB64 = Base64.getEncoder().encodeToString(ctx.getKeystore().getSignedPrekey().publicKey());
                keystoreSpkFingerprint.setText(PqSessionManager.computeKeyFingerprint(spkB64));
            }
            updateOpkMetrics();
        }

        // 3. Cryptographic Audit Trail
        loadAuditTrail();
    }

    private void updateVerificationBadge(boolean verified) {
        if (verified) {
            verificationStatusBadge.setText("VERIFIED ✓");
            verificationStatusBadge.getStyleClass().removeAll("unverified-badge");
            if (!verificationStatusBadge.getStyleClass().contains("verified-badge")) {
                verificationStatusBadge.getStyleClass().add("verified-badge");
            }
            btnToggleVerification.setText("Mark as Unverified");
        } else {
            verificationStatusBadge.setText("UNVERIFIED ⚠️");
            verificationStatusBadge.getStyleClass().removeAll("verified-badge");
            if (!verificationStatusBadge.getStyleClass().contains("unverified-badge")) {
                verificationStatusBadge.getStyleClass().add("unverified-badge");
            }
            btnToggleVerification.setText("Verify Safety Number");
        }
    }

    private void updateOpkMetrics() {
        ClientContext ctx = ClientContext.getInstance();
        ClientKeystore keystore = ctx.getKeystore();
        int available = (keystore != null && keystore.getOneTimePrekeys() != null)
                ? keystore.getOneTimePrekeys().size()
                : 0;

        availableOpkCountLabel.setText(String.valueOf(available));
        int consumed = Math.max(0, 10 - available);
        consumedOpkCountLabel.setText(String.valueOf(consumed));

        if (available >= 4) {
            opkHealthLabel.setText("OPTIMAL");
            opkHealthLabel.setStyle("-fx-text-fill: #10b981; -fx-font-weight: bold;");
        } else if (available > 0) {
            opkHealthLabel.setText("LOW POOL");
            opkHealthLabel.setStyle("-fx-text-fill: #f59e0b; -fx-font-weight: bold;");
        } else {
            opkHealthLabel.setText("DEPLETED");
            opkHealthLabel.setStyle("-fx-text-fill: #ef4444; -fx-font-weight: bold;");
        }
    }

    @FXML
    private void handleToggleVerification(ActionEvent event) {
        if (currentPeer == null || currentPeer.isBlank()) return;

        try {
            ClientContext ctx = ClientContext.getInstance();
            boolean currentStatus = ctx.getStorage().isPeerVerified(currentPeer);
            boolean newStatus = !currentStatus;
            ctx.getStorage().setPeerVerified(currentPeer, newStatus);
            updateVerificationBadge(newStatus);
        } catch (Exception e) {
            log.error("Failed to update peer verification state: {}", e.getMessage());
        }
    }

    @FXML
    private void handleRotateSpk(ActionEvent event) {
        keystoreSpkFingerprint.setText("Generating fresh ML-KEM-768 Prekey...");

        CompletableFuture.runAsync(() -> {
            try {
                ClientContext ctx = ClientContext.getInstance();
                ClientKeystore keystore = ctx.getKeystore();
                if (keystore == null) return;

                // 1. Rotate in local keystore
                var newSpk = keystore.rotateSignedPrekey();
                String prekeyB64 = Base64.getEncoder().encodeToString(newSpk.publicKey());
                String sigB64 = Base64.getEncoder().encodeToString(keystore.getSignedPrekeySignature());

                // 2. Upload to server
                RotateKeyBundleRequest req = new RotateKeyBundleRequest(prekeyB64, "ML-KEM-768", sigB64, null);
                ctx.getApiClient().rotateKeyBundle(req);

                Platform.runLater(() -> {
                    String spkFp = PqSessionManager.computeKeyFingerprint(prekeyB64);
                    keystoreSpkFingerprint.setText(spkFp);
                    loadAuditTrail();
                });
            } catch (Exception e) {
                Platform.runLater(() -> keystoreSpkFingerprint.setText("Rotation failed: " + e.getMessage()));
            }
        });
    }

    @FXML
    private void handleReplenishOpks(ActionEvent event) {
        CompletableFuture.runAsync(() -> {
            try {
                ClientContext ctx = ClientContext.getInstance();
                ClientKeystore keystore = ctx.getKeystore();
                if (keystore == null) return;

                KeyExchangeService kemService = new MlKemKeyExchangeService();
                List<OneTimePrekeyUploadDto> dtoList = new ArrayList<>();

                long startId = System.currentTimeMillis();
                for (int i = 0; i < 5; i++) {
                    long keyId = startId + i;
                    var kp = kemService.generateKeyPair();
                    keystore.addOneTimePrekey(keyId, kp);
                    dtoList.add(new OneTimePrekeyUploadDto(
                            (int) (keyId % Integer.MAX_VALUE),
                            Base64.getEncoder().encodeToString(kp.publicKey()),
                            "ML-KEM-768"
                    ));
                }

                UploadPrekeysRequest req = new UploadPrekeysRequest(dtoList);
                ctx.getApiClient().replenishPrekeys(req);

                Platform.runLater(() -> {
                    updateOpkMetrics();
                    loadAuditTrail();
                });
            } catch (Exception e) {
                log.error("Failed to replenish OPKs: {}", e.getMessage());
            }
        });
    }

    @FXML
    private void handleRefreshAuditTrail(ActionEvent event) {
        loadAuditTrail();
    }

    private void loadAuditTrail() {
        CompletableFuture.runAsync(() -> {
            try {
                ClientContext ctx = ClientContext.getInstance();
                if (ctx.getApiClient() == null) return;

                List<AuditLogDto> logs = ctx.getApiClient().getAuditTrail();
                Platform.runLater(() -> {
                    auditLogsList.getChildren().clear();
                    if (logs == null || logs.isEmpty()) {
                        Label emptyLbl = new Label("No cryptographic audit events recorded yet.");
                        emptyLbl.getStyleClass().add("card-hint");
                        auditLogsList.getChildren().add(emptyLbl);
                        return;
                    }

                    for (AuditLogDto entry : logs) {
                        VBox entryBox = new VBox(3);
                        entryBox.getStyleClass().add("audit-entry");

                        HBox header = new HBox(8);
                        header.setAlignment(Pos.CENTER_LEFT);

                        Label badge = new Label(entry.eventType());
                        badge.getStyleClass().add("audit-badge");

                        String timeStr = entry.createdAt() != null ? TIME_FMT.format(entry.createdAt()) : "Recent";
                        Label timeLbl = new Label(timeStr);
                        timeLbl.getStyleClass().add("card-hint");

                        header.getChildren().addAll(badge, timeLbl);

                        Label detailLbl = new Label(entry.details() != null ? entry.details() : "No details");
                        detailLbl.setStyle("-fx-font-size: 11px; -fx-text-fill: #cbd5e1;");
                        detailLbl.setWrapText(true);

                        entryBox.getChildren().addAll(header, detailLbl);
                        auditLogsList.getChildren().add(entryBox);
                    }
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    auditLogsList.getChildren().clear();
                    Label errLbl = new Label("Could not load audit logs: " + e.getMessage());
                    errLbl.setStyle("-fx-text-fill: #ef4444; -fx-font-size: 11px;");
                    auditLogsList.getChildren().add(errLbl);
                });
            }
        });
    }

    /**
     * Computes a deterministic 12-digit Safety Number for out-of-band identity verification:
     * SHA-256( min(localKey, peerKey) || max(localKey, peerKey) )
     */
    public static String computeSafetyNumber(String k1, String k2) {
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
    private void handleRunBenchmark(ActionEvent event) {
        btnRunBenchmark.setDisable(true);
        btnCopyMarkdown.setDisable(true);
        benchmarkStatusLabel.setText("Executing microbenchmarks (warmup + measurement iterations)...");
        benchmarkConsoleArea.setText("Initializing PqcBenchmarkRunner...\nMeasuring ML-KEM-768/1024, ML-DSA-65/87, AES-256-GCM, and PQ-X3DH session handshake...\nPlease wait (approx 2-3 seconds)...");

        CompletableFuture.runAsync(() -> {
            try {
                PqcBenchmarkRunner runner = new PqcBenchmarkRunner(15, 50);
                runner.runAll();
                String consoleReport = runner.generateConsoleReport();
                String markdownReport = runner.generateMarkdownReport();
                PqcBenchmarkRunner.SessionHandshakeBenchmarkResult sessionRes = runner.getSessionResult();

                Platform.runLater(() -> {
                    this.lastBenchmarkMarkdown = markdownReport;
                    benchmarkConsoleArea.setText(consoleReport);
                    benchmarkStatusLabel.setText("Microbenchmarks finished successfully!");
                    btnRunBenchmark.setDisable(false);
                    btnCopyMarkdown.setDisable(false);

                    if (sessionRes != null) {
                        handshakeLatencyBadge.setText("MEASURED");
                        handshakeLatencyBadge.setStyle("-fx-background-color: #064e3b; -fx-text-fill: #34d399; -fx-background-radius: 4px; -fx-padding: 2 6;");
                        handshakeTotalLatencyLabel.setText(String.format("%.2f ms (Alice: %.2f ms | Bob: %.2f ms)",
                                sessionRes.totalHandshakeLatencyMs(), sessionRes.aliceLatencyMs(), sessionRes.bobLatencyMs()));
                        handshakeWireOverheadLabel.setText(String.format("%,d Bytes (%.2f KB across 3 keys + 1 signature)",
                                sessionRes.totalWireBytes(), sessionRes.totalWireBytes() / 1024.0));
                    }
                });
            } catch (Exception e) {
                log.error("Live hardware benchmark failed", e);
                Platform.runLater(() -> {
                    benchmarkStatusLabel.setText("Benchmark execution failed: " + e.getMessage());
                    benchmarkConsoleArea.setText("Error running benchmark:\n" + e.toString());
                    btnRunBenchmark.setDisable(false);
                });
            }
        });
    }

    @FXML
    private void handleCopyBenchmarkMarkdown(ActionEvent event) {
        if (lastBenchmarkMarkdown != null && !lastBenchmarkMarkdown.isBlank()) {
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(lastBenchmarkMarkdown);
            clipboard.setContent(content);
            benchmarkStatusLabel.setText("Report copied to system clipboard (Markdown formatted)!");
        }
    }

    @FXML
    private void handleClose(ActionEvent event) {
        Stage stage = (Stage) peerUsernameLabel.getScene().getWindow();
        stage.close();
    }
}
