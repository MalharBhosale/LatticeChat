package com.securechat.client.controller;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

public class SplashController {

    @FXML
    private Label statusLabel;

    @FXML
    private Label cryptoStatusLabel;

    @FXML
    private Label serverStatusLabel;

    @FXML
    private Button btnCheckServer;

    @FXML
    private Button btnContinue;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    @FXML
    public void initialize() {
        statusLabel.setText("✓ SecureChat Initialized");
    }

    @FXML
    private void handleCheckServer() {
        btnCheckServer.setDisable(true);
        serverStatusLabel.setText("⏳ Checking backend server health...");

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:8080/api/v1/health"))
                .timeout(Duration.ofSeconds(4))
                .GET()
                .build();

        CompletableFuture.supplyAsync(() -> {
            try {
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                return response.statusCode() == 200 ? "✓ Connected to Backend Server (Status: 200 OK)" : "⚠ Server responded with status: " + response.statusCode();
            } catch (Exception e) {
                return "✗ Could not reach backend: " + (e.getMessage() != null ? e.getMessage() : "Connection refused");
            }
        }).thenAccept(result -> Platform.runLater(() -> {
            serverStatusLabel.setText(result);
            btnCheckServer.setDisable(false);
        }));
    }

    @FXML
    private void handleContinue() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("SecureChat Phase 1");
        alert.setHeaderText("Project Skeleton Verified");
        alert.setContentText("Phase 1 Project Skeleton is operating normally. Ready to proceed to Phase 2 (Database Layer)!");
        alert.showAndWait();
    }
}
