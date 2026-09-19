package com.securechat.client.net;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.securechat.common.dto.EncryptedMessageDto;
import com.securechat.common.dto.ReceiptNotificationDto;
import com.securechat.common.dto.UserPresenceDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Consumer;

/**
 * Lightweight STOMP client over Java 21 native WebSocket (java.net.http.WebSocket).
 * Handles:
 * - STOMP CONNECT with Authorization: Bearer JWT
 * - Subscription to /user/queue/messages, /user/queue/receipts, /topic/presence
 * - Incoming message dispatching via listener callbacks
 */
public class ClientWebSocketHandler implements WebSocket.Listener {

    private static final Logger log = LoggerFactory.getLogger(ClientWebSocketHandler.class);
    private static final String NULL_CHAR = "\u0000";

    private final String wsUrl;
    private final String jwtToken;
    private final ObjectMapper mapper;

    private WebSocket webSocket;
    private final StringBuilder frameBuffer = new StringBuilder();

    private Consumer<EncryptedMessageDto> messageListener;
    private Consumer<ReceiptNotificationDto> receiptListener;
    private Consumer<UserPresenceDto> presenceListener;
    private Runnable onConnectedCallback;
    private Consumer<String> onErrorCallback;

    public ClientWebSocketHandler(String wsUrl, String jwtToken) {
        this.wsUrl = wsUrl.endsWith("/") ? wsUrl.substring(0, wsUrl.length() - 1) : wsUrl;
        this.jwtToken = jwtToken;
        this.mapper = new ObjectMapper();
        this.mapper.registerModule(new JavaTimeModule());
    }

    public void setMessageListener(Consumer<EncryptedMessageDto> listener) {
        this.messageListener = listener;
    }

    public void setReceiptListener(Consumer<ReceiptNotificationDto> listener) {
        this.receiptListener = listener;
    }

    public void setPresenceListener(Consumer<UserPresenceDto> listener) {
        this.presenceListener = listener;
    }

    public void setOnConnected(Runnable callback) {
        this.onConnectedCallback = callback;
    }

    public void setOnError(Consumer<String> callback) {
        this.onErrorCallback = callback;
    }

    public CompletableFuture<WebSocket> connect() {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        return client.newWebSocketBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .buildAsync(URI.create(wsUrl), this)
                .thenApply(ws -> {
                    this.webSocket = ws;
                    sendStompConnect();
                    return ws;
                });
    }

    private void sendStompConnect() {
        String connectFrame = "CONNECT\n" +
                "accept-version:1.1,1.2\n" +
                "host:localhost\n" +
                "Authorization:Bearer " + jwtToken + "\n\n" +
                NULL_CHAR;
        webSocket.sendText(connectFrame, true);
    }

    private void subscribe(String id, String destination) {
        String subFrame = "SUBSCRIBE\n" +
                "id:" + id + "\n" +
                "destination:" + destination + "\n" +
                "ack:auto\n\n" +
                NULL_CHAR;
        webSocket.sendText(subFrame, true);
        log.info("Subscribed to STOMP destination: {}", destination);
    }

    @Override
    public void onOpen(WebSocket webSocket) {
        log.info("WebSocket connection established to {}", wsUrl);
        webSocket.request(1);
    }

    @Override
    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
        frameBuffer.append(data);

        if (last) {
            String fullMessage = frameBuffer.toString();
            frameBuffer.setLength(0);
            processStompFrames(fullMessage);
        }

        webSocket.request(1);
        return null;
    }

    private void processStompFrames(String rawData) {
        String[] frames = rawData.split(NULL_CHAR);
        for (String frame : frames) {
            frame = frame.trim();
            if (frame.isEmpty()) continue;

            if (frame.startsWith("CONNECTED")) {
                log.info("STOMP handshake CONNECTED");
                subscribe("sub-messages", "/user/queue/messages");
                subscribe("sub-receipts", "/user/queue/receipts");
                subscribe("sub-presence", "/topic/presence");
                if (onConnectedCallback != null) {
                    onConnectedCallback.run();
                }
            } else if (frame.startsWith("MESSAGE")) {
                handleStompMessage(frame);
            } else if (frame.startsWith("ERROR")) {
                log.error("STOMP ERROR received: {}", frame);
                if (onErrorCallback != null) {
                    onErrorCallback.accept(frame);
                }
            }
        }
    }

    private void handleStompMessage(String frame) {
        int emptyLineIdx = frame.indexOf("\n\n");
        if (emptyLineIdx == -1) {
            emptyLineIdx = frame.indexOf("\r\n\r\n");
        }

        String headersPart = emptyLineIdx != -1 ? frame.substring(0, emptyLineIdx) : frame;
        String body = emptyLineIdx != -1 ? frame.substring(emptyLineIdx).trim() : "";

        if (headersPart.contains("destination:/user/queue/messages") || headersPart.contains("/queue/messages")) {
            try {
                EncryptedMessageDto dto = mapper.readValue(body, EncryptedMessageDto.class);
                if (messageListener != null) {
                    messageListener.accept(dto);
                }
            } catch (Exception e) {
                log.warn("Failed to parse incoming EncryptedMessageDto: {}", e.getMessage());
            }
        } else if (headersPart.contains("destination:/user/queue/receipts") || headersPart.contains("/queue/receipts")) {
            try {
                ReceiptNotificationDto dto = mapper.readValue(body, ReceiptNotificationDto.class);
                if (receiptListener != null) {
                    receiptListener.accept(dto);
                }
            } catch (Exception e) {
                log.warn("Failed to parse incoming ReceiptNotificationDto: {}", e.getMessage());
            }
        } else if (headersPart.contains("destination:/topic/presence") || headersPart.contains("/topic/presence")) {
            try {
                UserPresenceDto dto = mapper.readValue(body, UserPresenceDto.class);
                if (presenceListener != null) {
                    presenceListener.accept(dto);
                }
            } catch (Exception e) {
                log.warn("Failed to parse incoming UserPresenceDto: {}", e.getMessage());
            }
        }
    }

    @Override
    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
        log.info("WebSocket closed: {} ({})", reason, statusCode);
        return null;
    }

    @Override
    public void onError(WebSocket webSocket, Throwable error) {
        log.error("WebSocket transport error: {}", error.getMessage());
        if (onErrorCallback != null) {
            onErrorCallback.accept(error.getMessage());
        }
    }

    public void disconnect() {
        if (webSocket != null) {
            webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "Client disconnecting");
        }
    }
}
