package com.securechat.client.context;

import com.securechat.client.crypto.ClientKeystore;
import com.securechat.client.net.ApiClient;
import com.securechat.client.net.ClientWebSocketHandler;
import com.securechat.client.protocol.PqSessionManager;
import com.securechat.client.storage.LocalStorageService;

/**
 * Global singleton managing active user state, cryptographic sessions,
 * network clients, and local storage during desktop app runtime.
 */
public class ClientContext {

    private static ClientContext instance;

    private String currentUsername;
    private String serverUrl = "http://localhost:8080/api/v1";
    private String wsUrl = "ws://localhost:8080/ws";

    private ApiClient apiClient;
    private ClientWebSocketHandler webSocketHandler;
    private ClientKeystore keystore;
    private LocalStorageService storage;
    private PqSessionManager sessionManager;

    private ClientContext() {}

    public static synchronized ClientContext getInstance() {
        if (instance == null) {
            instance = new ClientContext();
        }
        return instance;
    }

    public void initSession(String username, ApiClient apiClient, ClientKeystore keystore, LocalStorageService storage) {
        this.currentUsername = username;
        this.apiClient = apiClient;
        this.keystore = keystore;
        this.storage = storage;
        this.sessionManager = new PqSessionManager(username, keystore, storage);
    }

    public void setWebSocketHandler(ClientWebSocketHandler handler) {
        this.webSocketHandler = handler;
    }

    public String getCurrentUsername() {
        return currentUsername;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    public String getWsUrl() {
        return wsUrl;
    }

    public void setWsUrl(String wsUrl) {
        this.wsUrl = wsUrl;
    }

    public ApiClient getApiClient() {
        return apiClient;
    }

    public ClientWebSocketHandler getWebSocketHandler() {
        return webSocketHandler;
    }

    public ClientKeystore getKeystore() {
        return keystore;
    }

    public LocalStorageService getStorage() {
        return storage;
    }

    public PqSessionManager getSessionManager() {
        return sessionManager;
    }

    public void logout() {
        if (webSocketHandler != null) {
            webSocketHandler.disconnect();
            webSocketHandler = null;
        }
        if (storage != null) {
            try {
                storage.close();
            } catch (Exception ignored) {}
            storage = null;
        }
        currentUsername = null;
        apiClient = null;
        keystore = null;
        sessionManager = null;
    }
}
