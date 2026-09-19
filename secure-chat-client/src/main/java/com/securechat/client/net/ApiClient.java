package com.securechat.client.net;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.securechat.common.dto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * REST API client interacting with the LatticeChat backend server over HTTP/2.
 */
public class ApiClient {

    private static final Logger log = LoggerFactory.getLogger(ApiClient.class);

    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private String authToken;

    public ApiClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        this.mapper = new ObjectMapper();
        this.mapper.registerModule(new JavaTimeModule());
    }

    public void setAuthToken(String token) {
        this.authToken = token;
    }

    public String getAuthToken() {
        return authToken;
    }

    public boolean checkServerHealth() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/health"))
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    // --- Authentication ---

    public AuthResponse register(String username, String password, String email, String kemPubB64, String dsaPubB64) throws Exception {
        RegisterRequest req = new RegisterRequest(username, password, email, kemPubB64, dsaPubB64);
        ApiResponse<AuthResponse> res = post("/auth/register", req, new TypeReference<ApiResponse<AuthResponse>>() {});
        if (!res.success()) {
            throw new RuntimeException(res.message());
        }
        this.authToken = res.data().token();
        return res.data();
    }

    public AuthResponse login(String username, String password) throws Exception {
        AuthRequest req = new AuthRequest(username, password);
        ApiResponse<AuthResponse> res = post("/auth/login", req, new TypeReference<ApiResponse<AuthResponse>>() {});
        if (!res.success()) {
            throw new RuntimeException(res.message());
        }
        this.authToken = res.data().token();
        return res.data();
    }

    // --- Key Management ---

    public void publishKeyBundle(PublishKeyBundleRequest request) throws Exception {
        ApiResponse<Void> res = post("/keys/bundle", request, new TypeReference<ApiResponse<Void>>() {});
        if (!res.success()) {
            throw new RuntimeException(res.message());
        }
    }

    public KeyExchangeBundleDto getKeyBundle(String peerUsername) throws Exception {
        ApiResponse<KeyExchangeBundleDto> res = get("/keys/bundle/" + peerUsername, new TypeReference<ApiResponse<KeyExchangeBundleDto>>() {});
        if (!res.success()) {
            throw new RuntimeException(res.message());
        }
        return res.data();
    }

    public int replenishPrekeys(UploadPrekeysRequest request) throws Exception {
        ApiResponse<Integer> res = post("/keys/prekeys", request, new TypeReference<ApiResponse<Integer>>() {});
        if (!res.success()) {
            throw new RuntimeException(res.message());
        }
        return res.data() != null ? res.data() : 0;
    }

    public UserKeyBundleDto rotateKeyBundle(RotateKeyBundleRequest request) throws Exception {
        ApiResponse<UserKeyBundleDto> res = post("/keys/rotate", request, new TypeReference<ApiResponse<UserKeyBundleDto>>() {});
        if (!res.success()) {
            throw new RuntimeException(res.message());
        }
        return res.data();
    }

    public void revokeKeyBundle(com.securechat.common.dto.RevokeKeyBundleRequest request) throws Exception {
        ApiResponse<Void> res = post("/keys/revoke", request != null ? request : new com.securechat.common.dto.RevokeKeyBundleRequest("USER_REQUESTED"),
                new TypeReference<ApiResponse<Void>>() {});
        if (!res.success()) {
            throw new RuntimeException(res.message());
        }
    }

    public List<com.securechat.common.dto.AuditLogDto> getAuditTrail() throws Exception {
        ApiResponse<List<com.securechat.common.dto.AuditLogDto>> res = get("/keys/audit-trail",
                new TypeReference<ApiResponse<List<com.securechat.common.dto.AuditLogDto>>>() {});
        if (!res.success()) {
            throw new RuntimeException(res.message());
        }
        return res.data() != null ? res.data() : List.of();
    }

    // --- Attachments & File Transfer ---

    public UploadAttachmentResponse uploadAttachment(String recipientUsername,
                                                    String encryptedFilename,
                                                    String mimeType,
                                                    String nonceBase64,
                                                    byte[] encryptedData) throws Exception {
        String boundary = "----LatticeChatBoundary" + java.util.UUID.randomUUID().toString().replace("-", "");
        byte[] lineBreak = "\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

        // recipientUsername
        baos.write(("--" + boundary + "\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        baos.write("Content-Disposition: form-data; name=\"recipientUsername\"\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        baos.write(recipientUsername.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        baos.write(lineBreak);

        // encryptedFilename
        if (encryptedFilename != null) {
            baos.write(("--" + boundary + "\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            baos.write("Content-Disposition: form-data; name=\"encryptedFilename\"\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            baos.write(encryptedFilename.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            baos.write(lineBreak);
        }

        // mimeType
        if (mimeType != null) {
            baos.write(("--" + boundary + "\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            baos.write("Content-Disposition: form-data; name=\"mimeType\"\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            baos.write(mimeType.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            baos.write(lineBreak);
        }

        // nonce
        baos.write(("--" + boundary + "\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        baos.write("Content-Disposition: form-data; name=\"nonce\"\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        baos.write(nonceBase64.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        baos.write(lineBreak);

        // file
        baos.write(("--" + boundary + "\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        baos.write(("Content-Disposition: form-data; name=\"file\"; filename=\"" + (encryptedFilename != null ? encryptedFilename : "payload.enc") + "\"\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        baos.write("Content-Type: application/octet-stream\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        baos.write(encryptedData);
        baos.write(lineBreak);

        // closing boundary
        baos.write(("--" + boundary + "--\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] multipartBody = baos.toByteArray();

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/attachments/upload"))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(multipartBody));

        if (authToken != null) {
            builder.header("Authorization", "Bearer " + authToken);
        }

        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        ApiResponse<UploadAttachmentResponse> res = handleResponse(response, new TypeReference<ApiResponse<UploadAttachmentResponse>>() {});
        if (!res.success()) {
            throw new RuntimeException(res.message());
        }
        return res.data();
    }

    public byte[] downloadAttachment(String fileId) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/attachments/" + fileId))
                .timeout(Duration.ofSeconds(30))
                .GET();

        if (authToken != null) {
            builder.header("Authorization", "Bearer " + authToken);
        }

        HttpResponse<byte[]> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            return response.body();
        } else {
            throw new RuntimeException("Failed to download attachment (HTTP " + response.statusCode() + ")");
        }
    }

    public EncryptedAttachmentDto getAttachmentMetadata(String fileId) throws Exception {
        ApiResponse<EncryptedAttachmentDto> res = get("/attachments/" + fileId + "/meta",
                new TypeReference<ApiResponse<EncryptedAttachmentDto>>() {});
        if (!res.success()) {
            throw new RuntimeException(res.message());
        }
        return res.data();
    }



    // --- Messaging ---

    public EncryptedMessageDto sendMessage(SendMessageRequest request) throws Exception {
        ApiResponse<EncryptedMessageDto> res = post("/messages", request, new TypeReference<ApiResponse<EncryptedMessageDto>>() {});
        if (!res.success()) {
            throw new RuntimeException(res.message());
        }
        return res.data();
    }

    public List<EncryptedMessageDto> getPendingMessages() throws Exception {
        ApiResponse<List<EncryptedMessageDto>> res = get("/messages/pending", new TypeReference<ApiResponse<List<EncryptedMessageDto>>>() {});
        return res.success() && res.data() != null ? res.data() : List.of();
    }

    public List<EncryptedMessageDto> getConversation(String peerUsername) throws Exception {
        ApiResponse<List<EncryptedMessageDto>> res = get("/messages/conversation/" + peerUsername,
                new TypeReference<ApiResponse<List<EncryptedMessageDto>>>() {});
        return res.success() && res.data() != null ? res.data() : List.of();
    }

    public EncryptedMessageDto updateMessageStatus(String messageId, String status) throws Exception {
        DeliveryReceiptRequest req = new DeliveryReceiptRequest(status);
        ApiResponse<EncryptedMessageDto> res = put("/messages/" + messageId + "/status", req,
                new TypeReference<ApiResponse<EncryptedMessageDto>>() {});
        return res.data();
    }

    // --- Presence & Users ---

    public Set<String> getOnlineUsers() throws Exception {
        ApiResponse<Set<String>> res = get("/presence/online", new TypeReference<ApiResponse<Set<String>>>() {});
        return res.success() && res.data() != null ? res.data() : Set.of();
    }

    public boolean isUserOnline(String username) throws Exception {
        ApiResponse<Boolean> res = get("/presence/" + username, new TypeReference<ApiResponse<Boolean>>() {});
        return res.success() && Boolean.TRUE.equals(res.data());
    }

    public List<UserDto> searchUsers(String query) throws Exception {
        ApiResponse<List<UserDto>> res = get("/users/search?q=" + query, new TypeReference<ApiResponse<List<UserDto>>>() {});
        return res.success() && res.data() != null ? res.data() : List.of();
    }

    // --- HTTP Helper Methods ---

    private <T> T get(String endpoint, TypeReference<T> typeRef) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + endpoint))
                .timeout(Duration.ofSeconds(5))
                .GET();

        if (authToken != null) {
            builder.header("Authorization", "Bearer " + authToken);
        }

        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        return handleResponse(response, typeRef);
    }

    private <T> T post(String endpoint, Object body, TypeReference<T> typeRef) throws Exception {
        String json = mapper.writeValueAsString(body);
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + endpoint))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json));

        if (authToken != null) {
            builder.header("Authorization", "Bearer " + authToken);
        }

        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        return handleResponse(response, typeRef);
    }

    private <T> T put(String endpoint, Object body, TypeReference<T> typeRef) throws Exception {
        String json = mapper.writeValueAsString(body);
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + endpoint))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(json));

        if (authToken != null) {
            builder.header("Authorization", "Bearer " + authToken);
        }

        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        return handleResponse(response, typeRef);
    }

    private <T> T handleResponse(HttpResponse<String> response, TypeReference<T> typeRef) throws IOException {
        int status = response.statusCode();
        String body = response.body();

        if (status >= 200 && status < 300) {
            return mapper.readValue(body, typeRef);
        } else {
            try {
                ApiResponse<?> err = mapper.readValue(body, ApiResponse.class);
                throw new RuntimeException(err.message() != null ? err.message() : "Server returned status " + status);
            } catch (Exception e) {
                throw new RuntimeException("Server error (HTTP " + status + "): " + body);
            }
        }
    }
}
