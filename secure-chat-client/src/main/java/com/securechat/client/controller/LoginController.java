package com.securechat.client.controller;

import com.securechat.client.context.ClientContext;
import com.securechat.client.crypto.ClientKeystore;
import com.securechat.client.net.ApiClient;
import com.securechat.client.net.ClientWebSocketHandler;
import com.securechat.client.storage.LocalStorageService;
import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.dto.AuthResponse;
import com.securechat.common.dto.OneTimePrekeyUploadDto;
import com.securechat.common.dto.PublishKeyBundleRequest;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Controller managing User Authentication (Login / Registration) and initial PQC key setup.
 */
public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    @FXML
    private TextField serverUrlField;

    @FXML
    private TextField loginUsernameField;

    @FXML
    private PasswordField loginPasswordField;

    @FXML
    private Label loginStatusLabel;

    @FXML
    private Button btnLogin;

    @FXML
    private TextField regUsernameField;

    @FXML
    private TextField regEmailField;

    @FXML
    private TextField regFullNameField;

    @FXML
    private PasswordField regPasswordField;

    @FXML
    private Label regStatusLabel;

    @FXML
    private Button btnRegister;

    @FXML
    private TabPane authTabPane;

    @FXML
    public void initialize() {
        serverUrlField.setText("http://localhost:8080/api/v1");
    }

    @FXML
    private void handleLogin(ActionEvent event) {
        String username = loginUsernameField.getText().trim();
        String password = loginPasswordField.getText();
        String serverUrl = serverUrlField.getText().trim();

        if (username.isEmpty() || password.isEmpty()) {
            loginStatusLabel.setText("⚠ Username and password cannot be empty");
            return;
        }

        btnLogin.setDisable(true);
        loginStatusLabel.setText("⏳ Authenticating...");

        CompletableFuture.runAsync(() -> {
            try {
                ApiClient client = new ApiClient(serverUrl);
                AuthResponse auth = client.login(username, password);

                // Load or generate local keystore
                File keysFile = getKeystoreFile(username);
                ClientKeystore keystore;
                if (keysFile.exists()) {
                    keystore = ClientKeystore.loadFromFile(keysFile, password.toCharArray());
                } else {
                    keystore = ClientKeystore.generateNew(10);
                    keystore.saveToFile(keysFile, password.toCharArray());
                }

                LocalStorageService storage = LocalStorageService.forUser(username);
                ClientContext context = ClientContext.getInstance();
                context.setServerUrl(serverUrl);
                context.initSession(username, client, keystore, storage);

                // Connect STOMP WebSocket
                String wsUrl = serverUrl.replace("http://", "ws://").replace("/api/v1", "/ws");
                context.setWsUrl(wsUrl);

                ClientWebSocketHandler wsHandler = new ClientWebSocketHandler(wsUrl, auth.token());
                context.setWebSocketHandler(wsHandler);
                wsHandler.connect().exceptionally(ex -> {
                    log.warn("WebSocket initial connect failed: {}", ex.getMessage());
                    return null;
                });

                Platform.runLater(() -> {
                    try {
                        transitionToChatView();
                    } catch (Exception e) {
                        loginStatusLabel.setText("✗ UI Transition Error: " + e.getMessage());
                        btnLogin.setDisable(false);
                    }
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    loginStatusLabel.setText("✗ " + (e.getMessage() != null ? e.getMessage() : "Login failed"));
                    btnLogin.setDisable(false);
                });
            }
        });
    }

    @FXML
    private void handleRegister(ActionEvent event) {
        String username = regUsernameField.getText().trim();
        String email = regEmailField.getText().trim();
        String fullName = regFullNameField.getText().trim();
        String password = regPasswordField.getText();
        String serverUrl = serverUrlField.getText().trim();

        if (username.isEmpty() || email.isEmpty() || password.isEmpty()) {
            regStatusLabel.setText("⚠ All fields are required");
            return;
        }

        btnRegister.setDisable(true);
        regStatusLabel.setText("⏳ Generating Post-Quantum Keys (FIPS 203 & 204)...");

        CompletableFuture.runAsync(() -> {
            try {
                // 1. Generate client post-quantum key pairs
                ClientKeystore keystore = ClientKeystore.generateNew(10);
                File keysFile = getKeystoreFile(username);
                keystore.saveToFile(keysFile, password.toCharArray());

                String kemPub = Base64.getEncoder().encodeToString(keystore.getSignedPrekey().publicKey());
                String dsaPub = Base64.getEncoder().encodeToString(keystore.getIdentityKey().publicKey());

                // 2. Register with server
                ApiClient client = new ApiClient(serverUrl);
                AuthResponse auth = client.register(username, password, email, kemPub, dsaPub);

                // 3. Publish initial public key bundle to server
                List<OneTimePrekeyUploadDto> opkDtos = new ArrayList<>();
                for (Map.Entry<Long, KemKeyPair> entry : keystore.getOneTimePrekeys().entrySet()) {
                    opkDtos.add(new OneTimePrekeyUploadDto(
                            entry.getKey().intValue(),
                            Base64.getEncoder().encodeToString(entry.getValue().publicKey()),
                            "ML-KEM-768"
                    ));
                }

                PublishKeyBundleRequest bundleRequest = new PublishKeyBundleRequest(
                        Base64.getEncoder().encodeToString(keystore.getIdentityKey().publicKey()),
                        "ML-DSA-65",
                        Base64.getEncoder().encodeToString(keystore.getSignedPrekey().publicKey()),
                        "ML-KEM-768",
                        Base64.getEncoder().encodeToString(keystore.getSignedPrekeySignature()),
                        opkDtos
                );

                client.publishKeyBundle(bundleRequest);

                Platform.runLater(() -> {
                    regStatusLabel.setText("✓ Registered successfully! Please log in.");
                    btnRegister.setDisable(false);
                    loginUsernameField.setText(username);
                    authTabPane.getSelectionModel().select(0);
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    regStatusLabel.setText("✗ " + (e.getMessage() != null ? e.getMessage() : "Registration failed"));
                    btnRegister.setDisable(false);
                });
            }
        });
    }

    private void transitionToChatView() throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/chat.fxml"));
        Parent root = loader.load();

        Stage stage = (Stage) btnLogin.getScene().getWindow();
        Scene scene = new Scene(root, 950, 650);
        scene.getStylesheets().add(getClass().getResource("/css/style.css").toExternalForm());

        stage.setTitle("LatticeChat — Logged in as @" + ClientContext.getInstance().getCurrentUsername());
        stage.setScene(scene);
    }

    private File getKeystoreFile(String username) {
        String userHome = System.getProperty("user.home");
        File dir = new File(userHome, ".latticechat");
        dir.mkdirs();
        return new File(dir, "keys_" + username + ".enc");
    }
}
