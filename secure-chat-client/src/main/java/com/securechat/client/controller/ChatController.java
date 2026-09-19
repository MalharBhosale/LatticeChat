package com.securechat.client.controller;

import com.securechat.client.context.ClientContext;
import com.securechat.client.net.ApiClient;
import com.securechat.client.net.ClientWebSocketHandler;
import com.securechat.client.protocol.PqSessionManager;
import com.securechat.client.storage.LocalStorageService;
import com.securechat.client.storage.LocalMessage;
import com.securechat.common.dto.*;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.stage.Modality;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Controller managing the main messaging interface:
 * - Real-time incoming messages & receipts
 * - PQ-X3DH session initiation and AES-256-GCM message relay
 * - Contact search & online presence indicators
 */
public class ChatController {

    private static final Logger log = LoggerFactory.getLogger(ChatController.class);
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault());

    @FXML
    private Label currentUserLabel;

    @FXML
    private Label connectionStatusLabel;

    @FXML
    private TextField searchField;

    @FXML
    private ListView<String> contactListView;

    @FXML
    private Label chatHeaderLabel;

    @FXML
    private Label peerPresenceLabel;

    @FXML
    private Button btnSecurityDashboard;

    @FXML
    private Button btnSecurityInfo;

    @FXML
    private ScrollPane messageScrollPane;

    @FXML
    private VBox messageContainer;

    @FXML
    private TextField messageInputField;

    @FXML
    private Button btnAttach;

    @FXML
    private Button btnSend;


    private final ObservableList<String> contactList = FXCollections.observableArrayList();
    private final Set<String> onlinePeers = Collections.synchronizedSet(new HashSet<>());
    private String selectedPeer;
    private long currentSequenceNumber = 1L;

    @FXML
    public void initialize() {
        ClientContext ctx = ClientContext.getInstance();
        currentUserLabel.setText("@" + ctx.getCurrentUsername());

        setupContactListView();
        setupWebSocketListeners();
        loadRecentContacts();
        pollPendingMessages();
    }

    private void setupContactListView() {
        contactListView.setItems(contactList);
        contactListView.setCellFactory(lv -> new ListCell<>() {
            @Override
            protected void updateItem(String username, boolean empty) {
                super.updateItem(username, empty);
                if (empty || username == null) {
                    setText(null);
                    setGraphic(null);
                } else {
                    HBox box = new HBox(10);
                    box.setAlignment(Pos.CENTER_LEFT);

                    Circle dot = new Circle(5);
                    dot.setFill(onlinePeers.contains(username) ? Color.web("#10b981") : Color.web("#64748b"));

                    Label name = new Label("@" + username);
                    name.setTextFill(Color.WHITE);
                    name.setStyle("-fx-font-size: 14px; -fx-font-weight: bold;");

                    box.getChildren().addAll(dot, name);
                    setGraphic(box);
                }
            }
        });

        contactListView.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal != null && !newVal.equals(selectedPeer)) {
                selectContact(newVal);
            }
        });
    }

    private void setupWebSocketListeners() {
        ClientWebSocketHandler ws = ClientContext.getInstance().getWebSocketHandler();
        if (ws == null) return;

        ws.setOnConnected(() -> Platform.runLater(() -> {
            connectionStatusLabel.setText("🟢 Connected (STOMP / WSS)");
            connectionStatusLabel.setStyle("-fx-text-fill: #10b981;");
            refreshOnlinePresence();
        }));

        ws.setOnError(err -> Platform.runLater(() -> {
            connectionStatusLabel.setText("🔴 Reconnecting...");
            connectionStatusLabel.setStyle("-fx-text-fill: #ef4444;");
        }));

        // Real-time message push
        ws.setMessageListener(encryptedDto -> Platform.runLater(() -> handleIncomingMessage(encryptedDto)));

        // Real-time receipt notification
        ws.setReceiptListener(receipt -> Platform.runLater(() -> handleReceiptNotification(receipt)));

        // Real-time presence updates
        ws.setPresenceListener(presence -> Platform.runLater(() -> {
            if (presence.online()) {
                onlinePeers.add(presence.username());
            } else {
                onlinePeers.remove(presence.username());
            }
            contactListView.refresh();

            if (selectedPeer != null && selectedPeer.equals(presence.username())) {
                updatePeerPresenceLabel(presence.online());
            }
        }));
    }

    private void refreshOnlinePresence() {
        CompletableFuture.runAsync(() -> {
            try {
                ApiClient client = ClientContext.getInstance().getApiClient();
                Set<String> online = client.getOnlineUsers();
                Platform.runLater(() -> {
                    onlinePeers.clear();
                    onlinePeers.addAll(online);
                    contactListView.refresh();
                    if (selectedPeer != null) {
                        updatePeerPresenceLabel(onlinePeers.contains(selectedPeer));
                    }
                });
            } catch (Exception ignored) {}
        });
    }

    private void loadRecentContacts() {
        CompletableFuture.runAsync(() -> {
            try {
                LocalStorageService storage = ClientContext.getInstance().getStorage();
                List<String> peers = storage.getRecentPeers();
                Platform.runLater(() -> {
                    contactList.setAll(peers);
                    if (!contactList.isEmpty() && selectedPeer == null) {
                        contactListView.getSelectionModel().select(0);
                    }
                });
            } catch (Exception e) {
                log.error("Failed to load recent contacts: {}", e.getMessage());
            }
        });
    }

    private void selectContact(String peerUsername) {
        this.selectedPeer = peerUsername;
        chatHeaderLabel.setText("@" + peerUsername);
        btnSecurityInfo.setDisable(false);
        btnAttach.setDisable(false);
        messageInputField.setDisable(false);
        btnSend.setDisable(false);


        updatePeerPresenceLabel(onlinePeers.contains(peerUsername));
        loadConversationHistory(peerUsername);
    }

    private void updatePeerPresenceLabel(boolean online) {
        if (online) {
            peerPresenceLabel.setText("🟢 Online — Quantum-Secured");
            peerPresenceLabel.setStyle("-fx-text-fill: #10b981; -fx-font-size: 11px;");
        } else {
            peerPresenceLabel.setText("⚪ Offline — Messages will queue");
            peerPresenceLabel.setStyle("-fx-text-fill: #94a3b8; -fx-font-size: 11px;");
        }
    }

    private void loadConversationHistory(String peerUsername) {
        messageContainer.getChildren().clear();

        CompletableFuture.runAsync(() -> {
            try {
                LocalStorageService storage = ClientContext.getInstance().getStorage();
                List<LocalMessage> messages = storage.getMessagesForPeer(peerUsername);

                Platform.runLater(() -> {
                    for (LocalMessage msg : messages) {
                        renderMessageBubble(msg);
                    }
                    scrollToBottom();
                });
            } catch (Exception e) {
                log.error("Failed to load messages for peer {}: {}", peerUsername, e.getMessage());
            }
        });
    }

    @FXML
    private void handleSendMessage(ActionEvent event) {
        String text = messageInputField.getText().trim();
        if (text.isEmpty() || selectedPeer == null) return;

        messageInputField.clear();
        btnSend.setDisable(true);

        String peer = selectedPeer;
        long seq = currentSequenceNumber++;

        CompletableFuture.runAsync(() -> {
            try {
                ClientContext ctx = ClientContext.getInstance();
                ApiClient api = ctx.getApiClient();
                PqSessionManager sessionMgr = ctx.getSessionManager();

                String ephemeralKem = null;
                if (!sessionMgr.hasActiveSession(peer)) {
                    KeyExchangeBundleDto bundle = api.getKeyBundle(peer);
                    ephemeralKem = sessionMgr.initiateSession(peer, bundle);
                }

                SendMessageRequest request = sessionMgr.prepareOutgoingMessage(peer, text, ephemeralKem, seq);
                EncryptedMessageDto sentDto = api.sendMessage(request);

                Platform.runLater(() -> {
                    LocalMessage localMsg = new LocalMessage(
                            null,
                            sentDto.messageId(),
                            peer,
                            "OUTGOING",
                            text,
                            sentDto.status(),
                            seq,
                            sentDto.sentAt()
                    );
                    renderMessageBubble(localMsg);
                    scrollToBottom();
                    btnSend.setDisable(false);

                    if (!contactList.contains(peer)) {
                        contactList.add(0, peer);
                    }
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    btnSend.setDisable(false);
                    showErrorAlert("Message Transmission Error", "Failed to send encrypted message: " + e.getMessage());
                });
            }
        });
    }

    @FXML
    private void handleAttachFile(ActionEvent event) {
        if (selectedPeer == null) return;

        javafx.stage.FileChooser fileChooser = new javafx.stage.FileChooser();
        fileChooser.setTitle("LatticeChat — Select File to Encrypt & Send");
        java.io.File file = fileChooser.showOpenDialog(btnAttach.getScene().getWindow());
        if (file == null) return;

        if (file.length() > 25 * 1024 * 1024L) {
            showErrorAlert("File Size Exceeded", "Maximum file size is 25 MB. Selected file: " + (file.length() / (1024 * 1024)) + " MB");
            return;
        }

        String peer = selectedPeer;
        long seq = currentSequenceNumber++;

        CompletableFuture.runAsync(() -> {
            try {
                ClientContext ctx = ClientContext.getInstance();
                ApiClient api = ctx.getApiClient();
                PqSessionManager sessionMgr = ctx.getSessionManager();

                String ephemeralKem = null;
                if (!sessionMgr.hasActiveSession(peer)) {
                    KeyExchangeBundleDto bundle = api.getKeyBundle(peer);
                    ephemeralKem = sessionMgr.initiateSession(peer, bundle);
                }

                String sessionKeyB64 = ctx.getStorage().getSessionKey(peer)
                        .orElseThrow(() -> new IllegalStateException("Active session key not found for peer: " + peer));
                byte[] sessionKey = Base64.getDecoder().decode(sessionKeyB64);

                // 1. Client-Side Zero-Knowledge Encryption via AES-256-GCM
                com.securechat.client.crypto.FileCryptoService fileCrypto = new com.securechat.client.crypto.FileCryptoService();
                var payload = fileCrypto.encryptFile(file, sessionKey);
                String safeFilename = com.securechat.common.util.SafePathUtils.sanitizeFilename(file.getName());

                // 2. Upload ciphertext blob to quarantined storage
                String nonceB64 = Base64.getEncoder().encodeToString(payload.nonce());
                var uploadResp = api.uploadAttachment(peer, safeFilename, payload.mimeType(), nonceB64, payload.ciphertext());

                // 3. Send encrypted message payload referencing the attachment
                String fileMsgText = "[FILE]:" + uploadResp.fileId() + ":" + safeFilename + ":" + file.length() + ":" + payload.mimeType();
                SendMessageRequest request = sessionMgr.prepareOutgoingMessage(peer, fileMsgText, ephemeralKem, seq);
                EncryptedMessageDto sentDto = api.sendMessage(request);

                Platform.runLater(() -> {
                    LocalMessage localMsg = new LocalMessage(
                            null,
                            sentDto.messageId(),
                            peer,
                            "OUTGOING",
                            fileMsgText,
                            sentDto.status(),
                            seq,
                            sentDto.sentAt()
                    );
                    renderMessageBubble(localMsg);
                    scrollToBottom();
                });
            } catch (Exception e) {
                Platform.runLater(() -> showErrorAlert("Attachment Send Failed", e.getMessage()));
            }
        });
    }


    @FXML
    private void handleInputKeyPress(KeyEvent event) {
        if (event.getCode() == KeyCode.ENTER) {
            handleSendMessage(null);
        }
    }

    @FXML
    private void handleSearchUser(ActionEvent event) {
        String query = searchField.getText().trim();
        if (query.isEmpty()) return;

        CompletableFuture.runAsync(() -> {
            try {
                ApiClient api = ClientContext.getInstance().getApiClient();
                List<UserDto> users = api.searchUsers(query);

                Platform.runLater(() -> {
                    if (users.isEmpty()) {
                        showInfoAlert("Search Result", "No users found matching '" + query + "'");
                    } else {
                        for (UserDto u : users) {
                            if (!u.username().equals(ClientContext.getInstance().getCurrentUsername())) {
                                if (!contactList.contains(u.username())) {
                                    contactList.add(0, u.username());
                                }
                                contactListView.getSelectionModel().select(u.username());
                                break;
                            }
                        }
                    }
                });
            } catch (Exception e) {
                Platform.runLater(() -> showErrorAlert("Search Failed", e.getMessage()));
            }
        });
    }

    private void handleIncomingMessage(EncryptedMessageDto incoming) {
        String sender = incoming.senderUsername();

        CompletableFuture.runAsync(() -> {
            try {
                ClientContext ctx = ClientContext.getInstance();
                ApiClient api = ctx.getApiClient();
                PqSessionManager sessionMgr = ctx.getSessionManager();

                // If sender identity key not known yet, fetch their key bundle
                String peerIdKey = ctx.getStorage().getPeerIdentityKey(sender).orElse(null);
                if (peerIdKey == null) {
                    KeyExchangeBundleDto bundle = api.getKeyBundle(sender);
                    peerIdKey = bundle.identityKey();
                }

                LocalMessage decryptedMsg = sessionMgr.processIncomingMessage(incoming, peerIdKey);

                Platform.runLater(() -> {
                    if (!contactList.contains(sender)) {
                        contactList.add(0, sender);
                    }

                    if (selectedPeer != null && selectedPeer.equals(sender)) {
                        renderMessageBubble(decryptedMsg);
                        scrollToBottom();
                        // Send read receipt back to sender
                        CompletableFuture.runAsync(() -> {
                            try {
                                api.updateMessageStatus(incoming.messageId(), "READ");
                            } catch (Exception ignored) {}
                        });
                    }
                });
            } catch (Exception e) {
                log.error("Failed to decrypt incoming message from {}: {}", sender, e.getMessage());
            }
        });
    }

    private void handleReceiptNotification(ReceiptNotificationDto receipt) {
        CompletableFuture.runAsync(() -> {
            try {
                ClientContext.getInstance().getStorage().updateMessageStatus(receipt.messageId(), receipt.status());
                Platform.runLater(() -> {
                    // Update checkmarks in current view
                    if (selectedPeer != null) {
                        loadConversationHistory(selectedPeer);
                    }
                });
            } catch (Exception ignored) {}
        });
    }

    private void pollPendingMessages() {
        CompletableFuture.runAsync(() -> {
            try {
                ApiClient api = ClientContext.getInstance().getApiClient();
                List<EncryptedMessageDto> pending = api.getPendingMessages();
                for (EncryptedMessageDto msg : pending) {
                    handleIncomingMessage(msg);
                }
            } catch (Exception e) {
                log.warn("Pending messages poll failed: {}", e.getMessage());
            }
        });
    }

    private void renderMessageBubble(LocalMessage msg) {
        boolean isOutgoing = "OUTGOING".equalsIgnoreCase(msg.direction());

        HBox bubbleRow = new HBox();
        bubbleRow.setAlignment(isOutgoing ? Pos.CENTER_RIGHT : Pos.CENTER_LEFT);
        bubbleRow.setPadding(new Insets(4, 12, 4, 12));

        VBox bubble = new VBox(6);
        bubble.setMaxWidth(480);
        bubble.setPadding(new Insets(10, 14, 8, 14));

        if (isOutgoing) {
            bubble.setStyle("-fx-background-color: linear-gradient(to bottom right, #2563eb, #1d4ed8); -fx-background-radius: 14 14 2 14;");
        } else {
            bubble.setStyle("-fx-background-color: #334155; -fx-background-radius: 14 14 14 2;");
        }

        if (msg.plaintext().startsWith("[FILE]:")) {
            String[] parts = msg.plaintext().split(":", 5);
            String fileId = parts.length > 1 ? parts[1] : "unknown";
            String fileName = parts.length > 2 ? parts[2] : "attachment.bin";
            long sizeBytes = 0;
            try {
                sizeBytes = parts.length > 3 ? Long.parseLong(parts[3]) : 0;
            } catch (NumberFormatException ignored) {}

            String sizeFormatted = formatFileSize(sizeBytes);

            HBox fileCard = new HBox(10);
            fileCard.setAlignment(Pos.CENTER_LEFT);
            fileCard.setStyle("-fx-background-color: rgba(15, 23, 42, 0.45); -fx-padding: 8 10; -fx-background-radius: 8px;");

            Label iconLabel = new Label("📁");
            iconLabel.setStyle("-fx-font-size: 20px;");

            VBox fileMeta = new VBox(2);
            Label nameLabel = new Label(fileName);
            nameLabel.setTextFill(Color.WHITE);
            nameLabel.setStyle("-fx-font-size: 13px; -fx-font-weight: bold;");

            Label sizeLabel = new Label(sizeFormatted + " • AES-256-GCM Encrypted");
            sizeLabel.setTextFill(Color.web(isOutgoing ? "#bfdbfe" : "#94a3b8"));
            sizeLabel.setStyle("-fx-font-size: 10.5px;");

            fileMeta.getChildren().addAll(nameLabel, sizeLabel);
            HBox.setHgrow(fileMeta, Priority.ALWAYS);

            Button btnDownload = new Button("⬇ Download");
            btnDownload.setStyle("-fx-background-color: #0284c7; -fx-text-fill: white; -fx-font-size: 11px; -fx-font-weight: bold; -fx-background-radius: 6px; -fx-cursor: hand;");
            btnDownload.setOnAction(e -> downloadAndDecryptAttachment(fileId, fileName, msg.peerUsername()));

            fileCard.getChildren().addAll(iconLabel, fileMeta, btnDownload);
            bubble.getChildren().add(fileCard);
        } else {
            Label textLabel = new Label(msg.plaintext());
            textLabel.setWrapText(true);
            textLabel.setTextFill(Color.WHITE);
            textLabel.setStyle("-fx-font-size: 13.5px;");
            bubble.getChildren().add(textLabel);
        }

        HBox metaRow = new HBox(8);
        metaRow.setAlignment(Pos.CENTER_RIGHT);

        String timeStr = msg.timestamp() != null ? TIME_FORMAT.format(msg.timestamp()) : "";
        Label timeLabel = new Label(timeStr);
        timeLabel.setTextFill(Color.web(isOutgoing ? "#bfdbfe" : "#94a3b8"));
        timeLabel.setStyle("-fx-font-size: 10px;");
        metaRow.getChildren().add(timeLabel);

        Button btnInspect = new Button("🔬");
        btnInspect.setTooltip(new Tooltip("Inspect Cryptographic Envelope"));
        btnInspect.setStyle("-fx-background-color: transparent; -fx-text-fill: #94a3b8; -fx-font-size: 10px; -fx-cursor: hand; -fx-padding: 0 4;");
        btnInspect.setOnAction(e -> openMessageInspector(msg));
        metaRow.getChildren().add(btnInspect);

        if (isOutgoing) {
            String status = msg.status();
            String icon = "✓";
            Color iconColor = Color.web("#bfdbfe");
            if ("DELIVERED".equalsIgnoreCase(status)) {
                icon = "✓✓";
            } else if ("READ".equalsIgnoreCase(status)) {
                icon = "✓✓";
                iconColor = Color.web("#38bdf8"); // bright cyan double check
            }

            Label statusLabel = new Label(icon);
            statusLabel.setTextFill(iconColor);
            statusLabel.setStyle("-fx-font-size: 10px; -fx-font-weight: bold;");
            metaRow.getChildren().add(statusLabel);
        }

        bubble.getChildren().add(metaRow);
        bubbleRow.getChildren().add(bubble);
        messageContainer.getChildren().add(bubbleRow);
    }

    private void downloadAndDecryptAttachment(String fileId, String suggestedFilename, String peerUsername) {
        String safeSuggestedName = com.securechat.common.util.SafePathUtils.sanitizeFilename(suggestedFilename);
        javafx.stage.FileChooser chooser = new javafx.stage.FileChooser();
        chooser.setTitle("Save Decrypted File");
        chooser.setInitialFileName(safeSuggestedName);
        java.io.File saveFile = chooser.showSaveDialog(currentUserLabel.getScene().getWindow());
        if (saveFile == null) return;

        CompletableFuture.runAsync(() -> {
            try {
                ClientContext ctx = ClientContext.getInstance();
                ApiClient api = ctx.getApiClient();

                // 1. Fetch attachment metadata to obtain GCM nonce
                EncryptedAttachmentDto meta = api.getAttachmentMetadata(fileId);
                byte[] nonce = Base64.getDecoder().decode(meta.nonceBase64());

                // 2. Retrieve peer's session key
                String sessionKeyB64 = ctx.getStorage().getSessionKey(peerUsername)
                        .orElseThrow(() -> new IllegalStateException("Active session key not found for peer: " + peerUsername));
                byte[] sessionKey = Base64.getDecoder().decode(sessionKeyB64);

                // 3. Stream encrypted ciphertext directly to temporary disk file
                java.nio.file.Path tempEncFile = java.nio.file.Files.createTempFile("lattice_enc_", ".tmp");
                try {
                    api.downloadAttachmentStream(fileId, tempEncFile);

                    // 4. Decrypt locally and verify 128-bit authentication tag
                    com.securechat.client.crypto.FileCryptoService fileCrypto = new com.securechat.client.crypto.FileCryptoService();
                    byte[] ciphertext = java.nio.file.Files.readAllBytes(tempEncFile);
                    fileCrypto.decryptToFile(ciphertext, nonce, sessionKey, saveFile);
                } finally {
                    java.nio.file.Files.deleteIfExists(tempEncFile);
                }

                Platform.runLater(() -> showInfoAlert("Decryption Successful",
                        "File successfully decrypted and saved to:\n" + saveFile.getAbsolutePath()));
            } catch (Exception e) {
                Platform.runLater(() -> showErrorAlert("Download & Decryption Error", e.getMessage()));
            }
        });
    }

    private void openMessageInspector(LocalMessage msg) {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/message_inspector.fxml"));
            Parent root = loader.load();

            MessageInspectorController controller = loader.getController();
            controller.initData(msg);

            Stage dialog = new Stage();
            dialog.initModality(Modality.WINDOW_MODAL);
            dialog.initOwner(currentUserLabel.getScene().getWindow());
            dialog.setTitle("LatticeChat — Cryptographic Inspector (" + msg.messageId() + ")");

            Scene scene = new Scene(root, 640, 600);
            scene.getStylesheets().add(getClass().getResource("/css/style.css").toExternalForm());
            dialog.setScene(scene);
            dialog.showAndWait();
        } catch (Exception e) {
            showErrorAlert("Inspector Error", e.getMessage());
        }
    }

    private String formatFileSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
    }


    private void scrollToBottom() {
        Platform.runLater(() -> messageScrollPane.setVvalue(1.0));
    }

    @FXML
    private void handleOpenSecurityDashboard(ActionEvent event) {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/security_dashboard.fxml"));
            Parent root = loader.load();

            SecurityDashboardController controller = loader.getController();
            controller.initData(selectedPeer);

            Stage dialog = new Stage();
            dialog.initModality(Modality.WINDOW_MODAL);
            dialog.initOwner(currentUserLabel.getScene().getWindow());
            dialog.setTitle("LatticeChat — Cryptographic Security Dashboard & Inspector");

            Scene scene = new Scene(root, 760, 680);
            scene.getStylesheets().add(getClass().getResource("/css/style.css").toExternalForm());
            dialog.setScene(scene);
            dialog.showAndWait();
        } catch (Exception e) {
            showErrorAlert("Dashboard Error", "Could not open security dashboard: " + e.getMessage());
        }
    }

    @FXML
    private void handleOpenSecurityInfo(ActionEvent event) {
        if (selectedPeer == null) return;

        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/security_info.fxml"));
            Parent root = loader.load();

            SecurityInfoController controller = loader.getController();
            controller.initData(selectedPeer);

            Stage dialog = new Stage();
            dialog.initModality(Modality.WINDOW_MODAL);
            dialog.initOwner(btnSecurityInfo.getScene().getWindow());
            dialog.setTitle("LatticeChat — PQC Cryptographic Verification");

            Scene scene = new Scene(root, 540, 420);
            scene.getStylesheets().add(getClass().getResource("/css/style.css").toExternalForm());
            dialog.setScene(scene);
            dialog.showAndWait();
        } catch (Exception e) {
            showErrorAlert("Dialog Error", e.getMessage());
        }
    }

    @FXML
    private void handleLogout(ActionEvent event) {
        ClientContext.getInstance().logout();
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/login.fxml"));
            Parent root = loader.load();
            Stage stage = (Stage) currentUserLabel.getScene().getWindow();
            Scene scene = new Scene(root, 800, 600);
            scene.getStylesheets().add(getClass().getResource("/css/style.css").toExternalForm());
            stage.setTitle("LatticeChat — Secure Login");
            stage.setScene(scene);
        } catch (Exception e) {
            log.error("Logout navigation failed: {}", e.getMessage());
        }
    }

    private void showErrorAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void showInfoAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}
