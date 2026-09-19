package com.securechat.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.dto.DeliveryReceiptRequest;
import com.securechat.common.dto.PublishKeyBundleRequest;
import com.securechat.common.dto.SendMessageRequest;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.MessageRepository;
import com.securechat.server.repository.OneTimePrekeyRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
import com.securechat.server.repository.UserRepository;
import com.securechat.server.security.JwtTokenProvider;
import com.securechat.server.service.KeyManagementService;
import com.securechat.server.service.MessageService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class MessageControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserKeyBundleRepository keyBundleRepository;

    @Autowired
    private OneTimePrekeyRepository prekeyRepository;

    @Autowired
    private MessageRepository messageRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private KeyManagementService keyManagementService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private ObjectMapper objectMapper;

    private final MlDsaSignatureService dsaService = new MlDsaSignatureService();
    private final MlKemKeyExchangeService kemService = new MlKemKeyExchangeService();

    private UserEntity alice;
    private UserEntity bob;
    private String aliceToken;
    private String bobToken;
    private SignatureKeyPair aliceDsa;

    @BeforeEach
    void setUp() {
        messageRepository.deleteAll();
        prekeyRepository.deleteAll();
        keyBundleRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        alice = userRepository.save(new UserEntity("alice_msg", "alice_msg@latticechat.internal", "hash1", "Alice Msg"));
        bob = userRepository.save(new UserEntity("bob_msg", "bob_msg@latticechat.internal", "hash2", "Bob Msg"));

        aliceToken = jwtTokenProvider.generateToken(alice);
        bobToken = jwtTokenProvider.generateToken(bob);

        // Publish Alice's key bundle
        aliceDsa = dsaService.generateKeyPair();
        KemKeyPair aliceKem = kemService.generateKeyPair();
        byte[] sig = dsaService.sign(aliceKem.publicKey(), aliceDsa.privateKey());

        keyManagementService.publishKeyBundle("alice_msg", new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(aliceDsa.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(aliceKem.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig),
                null
        ));
    }

    @Test
    @DisplayName("POST /api/v1/messages: Should return 401 Unauthorized when missing token")
    void testSendMessageUnauthenticated() throws Exception {
        mockMvc.perform(post("/api/v1/messages")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /api/v1/messages: Should relay encrypted message and return 201 Created")
    void testSendMessageSuccess() throws Exception {
        String msgId = UUID.randomUUID().toString();
        long seq = 1L;
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);
        String ct = Base64.getEncoder().encodeToString("Ciphertext123".getBytes(StandardCharsets.UTF_8));

        String payload = MessageService.buildPayloadString(msgId, seq, nonce, ct);
        byte[] sigBytes = dsaService.sign(payload.getBytes(StandardCharsets.UTF_8), aliceDsa.privateKey());
        String sig = Base64.getEncoder().encodeToString(sigBytes);

        SendMessageRequest request = new SendMessageRequest("bob_msg", msgId, ct, nonce, null, sig, seq);

        mockMvc.perform(post("/api/v1/messages")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.messageId").value(msgId))
                .andExpect(jsonPath("$.data.senderUsername").value("alice_msg"))
                .andExpect(jsonPath("$.data.recipientUsername").value("bob_msg"))
                .andExpect(jsonPath("$.data.status").value("SENT"));
    }

    @Test
    @DisplayName("POST /api/v1/messages: Should reject replay attack when duplicate messageId is sent")
    void testSendMessageReplayRejected() throws Exception {
        String msgId = "replay-uuid-ctrl";
        long seq = 1L;
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);
        String ct = Base64.getEncoder().encodeToString("Ciphertext123".getBytes(StandardCharsets.UTF_8));

        String payload = MessageService.buildPayloadString(msgId, seq, nonce, ct);
        byte[] sigBytes = dsaService.sign(payload.getBytes(StandardCharsets.UTF_8), aliceDsa.privateKey());
        String sig = Base64.getEncoder().encodeToString(sigBytes);

        SendMessageRequest request = new SendMessageRequest("bob_msg", msgId, ct, nonce, null, sig, seq);

        // First send: success
        mockMvc.perform(post("/api/v1/messages")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        // Second send with same ID: rejected
        mockMvc.perform(post("/api/v1/messages")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("replay attack")));
    }

    @Test
    @DisplayName("GET /api/v1/messages/pending: Should retrieve offline queued messages for Bob")
    void testGetPendingMessages() throws Exception {
        // Alice sends message to Bob
        String msgId = UUID.randomUUID().toString();
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);
        String ct = Base64.getEncoder().encodeToString("Hello Bob".getBytes(StandardCharsets.UTF_8));
        String sig = Base64.getEncoder().encodeToString(dsaService.sign(
                MessageService.buildPayloadString(msgId, 1L, nonce, ct).getBytes(StandardCharsets.UTF_8),
                aliceDsa.privateKey()));

        SendMessageRequest request = new SendMessageRequest("bob_msg", msgId, ct, nonce, null, sig, 1L);

        mockMvc.perform(post("/api/v1/messages")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        // Bob polls pending messages
        mockMvc.perform(get("/api/v1/messages/pending")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data[0].messageId").value(msgId))
                .andExpect(jsonPath("$.data[0].status").value("DELIVERED"));
    }

    @Test
    @DisplayName("GET /api/v1/messages/conversation/{peerUsername} & PUT /api/v1/messages/{messageId}/status")
    void testConversationHistoryAndStatusUpdate() throws Exception {
        String msgId = UUID.randomUUID().toString();
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);
        String ct = Base64.getEncoder().encodeToString("Chat Msg".getBytes(StandardCharsets.UTF_8));
        String sig = Base64.getEncoder().encodeToString(dsaService.sign(
                MessageService.buildPayloadString(msgId, 1L, nonce, ct).getBytes(StandardCharsets.UTF_8),
                aliceDsa.privateKey()));

        SendMessageRequest sendReq = new SendMessageRequest("bob_msg", msgId, ct, nonce, null, sig, 1L);
        mockMvc.perform(post("/api/v1/messages")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(sendReq)))
                .andExpect(status().isCreated());

        // Conversation history check
        mockMvc.perform(get("/api/v1/messages/conversation/bob_msg")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data[0].messageId").value(msgId));

        // Bob marks message as READ
        DeliveryReceiptRequest receiptReq = new DeliveryReceiptRequest("READ");
        mockMvc.perform(put("/api/v1/messages/" + msgId + "/status")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(receiptReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.status").value("READ"));
    }
}
