package com.securechat.client.controller;

import com.securechat.client.service.LabAttackResult;
import com.securechat.client.service.SecurityLabService;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.Stage;

import java.util.concurrent.CompletableFuture;

/**
 * Controller for the Educational Security Lab & Attack Simulator.
 * Allows users and evaluators to interactively simulate real-world attacks:
 * 1. Replay Attacks.
 * 2. Ciphertext Bit-Flipping.
 * 3. ML-DSA-65 Forged Signatures.
 * 4. Insecure Direct Object References (IDOR).
 */
public class SecurityLabController {

    @FXML
    private RadioButton radioReplay;

    @FXML
    private RadioButton radioTamper;

    @FXML
    private RadioButton radioSignature;

    @FXML
    private RadioButton radioIdor;

    @FXML
    private ToggleGroup attackScenarioGroup;

    @FXML
    private TextField inputPayloadField;

    @FXML
    private TextField inputParamField;

    @FXML
    private Label inputParamLabel;

    @FXML
    private Button btnExecuteSimulation;

    @FXML
    private Label defenseBanner;

    @FXML
    private Label shieldNameLabel;

    @FXML
    private Label explanationLabel;

    @FXML
    private TextArea forensicTerminal;

    @FXML
    private Label metricsLabel;

    private final SecurityLabService labService = new SecurityLabService();

    @FXML
    public void initialize() {
        // Dynamic parameter updates when attack scenario changes
        attackScenarioGroup.selectedToggleProperty().addListener((obs, oldVal, newVal) -> {
            if (radioReplay.isSelected()) {
                inputParamLabel.setText("Target Peer Username:");
                inputParamField.setText("bob");
                inputPayloadField.setText("Transfer Approval: $50,000 to Alice");
            } else if (radioTamper.isSelected()) {
                inputParamLabel.setText("Bit Index to Flip (Byte offset):");
                inputParamField.setText("4");
                inputPayloadField.setText("Confidential Wire: $100,000 to Account #4429");
            } else if (radioSignature.isSelected()) {
                inputParamLabel.setText("Simulated Key Mutation Byte:");
                inputParamField.setText("10");
                inputPayloadField.setText("Authorization Token: Alice Grants Access");
            } else if (radioIdor.isSelected()) {
                inputParamLabel.setText("Simulated Target Attachment File ID:");
                inputParamField.setText("att-doc-" + java.util.UUID.randomUUID().toString().substring(0, 8));
                inputPayloadField.setText("Unauthorized Requester: eve");
            }
        });
    }

    @FXML
    private void handleExecuteSimulation(ActionEvent event) {
        btnExecuteSimulation.setDisable(true);
        btnExecuteSimulation.setText("⚡ Simulating Attack...");
        defenseBanner.setText("ATTACK IN PROGRESS — EVALUATING DEFENSE...");
        defenseBanner.setStyle("-fx-text-fill: #f59e0b; -fx-font-weight: bold;");

        String payload = inputPayloadField.getText();
        String param = inputParamField.getText();

        CompletableFuture.supplyAsync(() -> {
            if (radioReplay.isSelected()) {
                return labService.simulateReplayAttack(param);
            } else if (radioTamper.isSelected()) {
                int byteOffset = 4;
                try {
                    byteOffset = Integer.parseInt(param.trim());
                } catch (NumberFormatException ignored) {}
                return labService.simulateCiphertextTamper(payload, byteOffset);
            } else if (radioSignature.isSelected()) {
                return labService.simulateBadSignature(payload);
            } else {
                return labService.simulateIdorAccess(param);
            }
        }).thenAccept(result -> Platform.runLater(() -> renderSimulationResult(result)))
          .exceptionally(ex -> {
              Platform.runLater(() -> {
                  btnExecuteSimulation.setDisable(false);
                  btnExecuteSimulation.setText("🚀 Launch Attack Simulation");
                  defenseBanner.setText("SIMULATION ERROR");
                  defenseBanner.setStyle("-fx-text-fill: #ef4444; -fx-font-weight: bold;");
                  forensicTerminal.appendText("[ERROR] Simulation aborted: " + ex.getMessage() + "\n");
              });
              return null;
          });
    }

    private void renderSimulationResult(LabAttackResult result) {
        btnExecuteSimulation.setDisable(false);
        btnExecuteSimulation.setText("🚀 Launch Attack Simulation");

        if (result.defenseSuccessful()) {
            defenseBanner.setText("ATTACK NEUTRALIZED ✓ — SHIELD TRIGGERED");
            defenseBanner.setStyle("-fx-text-fill: #10b981; -fx-font-weight: bold; -fx-font-size: 13px;");
        } else {
            defenseBanner.setText("ATTACK SUCCEEDED ⚠️ (VULNERABILITY DETECTED)");
            defenseBanner.setStyle("-fx-text-fill: #ef4444; -fx-font-weight: bold; -fx-font-size: 13px;");
        }

        shieldNameLabel.setText("Active Defense: " + result.defenseTriggered());
        explanationLabel.setText(result.explanation());
        metricsLabel.setText(result.elapsedMillis() + " ms");

        StringBuilder sb = new StringBuilder();
        sb.append("================================================================================\n");
        sb.append("SCENARIO: ").append(result.attackType().getDisplayName()).append("\n");
        sb.append("STATUS:   ").append(result.defenseSuccessful() ? "DEFENSE SUCCESSFUL (ATTACK BLOCKED)" : "FAILED").append("\n");
        sb.append("SHIELD:   ").append(result.defenseTriggered()).append("\n");
        sb.append("DETAILS:  ").append(result.technicalDetails()).append("\n");
        sb.append("--------------------------------------------------------------------------------\n");
        for (String step : result.forensicLogSteps()) {
            sb.append(step).append("\n");
        }
        sb.append("================================================================================\n\n");

        forensicTerminal.appendText(sb.toString());
        forensicTerminal.setScrollTop(Double.MAX_VALUE);
    }

    @FXML
    private void handleClearConsole(ActionEvent event) {
        forensicTerminal.clear();
        defenseBanner.setText("SYSTEM IDLE — READY FOR SIMULATION");
        defenseBanner.setStyle("-fx-text-fill: #94a3b8; -fx-font-weight: bold;");
        shieldNameLabel.setText("Active Defense Shield: Ready");
        explanationLabel.setText("Select an attack scenario on the left and click 'Launch Attack Simulation' to observe cryptographic defenses.");
        metricsLabel.setText("0 ms");
    }

    @FXML
    private void handleClose(ActionEvent event) {
        Stage stage = (Stage) btnExecuteSimulation.getScene().getWindow();
        stage.close();
    }
}
