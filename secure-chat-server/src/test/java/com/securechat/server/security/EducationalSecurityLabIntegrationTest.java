package com.securechat.server.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securechat.common.crypto.SignatureService;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.dto.DeliveryReceiptRequest;
import com.securechat.common.dto.SendMessageRequest;
import com.securechat.server.entity.*;
import com.securechat.server.repository.AttachmentRepository;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.MessageRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
import com.securechat.server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Institutional Educational Security Lab Integration Tests.
 * Programmatically simulates adversarial attack vectors against server-side endpoints
 * and verifies that defense shields reject malicious requests while recording immutable audit logs:
 * 1. Replay Attack & Duplicate Frame Injection.
 * 2. Forged / Corrupted ML-DSA-65 Signature Injection.
 * 3. Insecure Direct Object Reference (IDOR) on Encrypted Attachments.
 * 4. Insecure Direct Object Reference (IDOR) on Attachment Streaming.
 * 5. Insecure Direct Object Reference (IDOR) on Message Delivery Status.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EducationalSecurityLabIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserKeyBundleRepository keyBundleRepository;

    @Autowired
    private MessageRepository messageRepository;

    @Autowired
    private AttachmentRepository attachmentRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private ObjectMapper objectMapper;

    private UserEntity alice;
    private UserEntity bob;
    private UserEntity eve;

    private String aliceToken;
    private String bobToken;
    private String eveToken;

    private SignatureService.SignatureKeyPair aliceDsaKey;
    private final SignatureService signatureService = new MlDsaSignatureService();

    @BeforeEach
    void setUp() {
        attachmentRepository.deleteAll();
        messageRepository.deleteAll();
        keyBundleRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        alice = userRepository.save(new UserEntity("alice", "alice@example.com", "hash1", "Alice"));
        bob = userRepository.save(new UserEntity("bob", "bob@example.com", "hash2", "Bob"));
        eve = userRepository.save(new UserEntity("eve", "eve@example.com", "hash3", "Eve"));

        aliceToken = jwtTokenProvider.generateToken(alice);
        bobToken = jwtTokenProvider.generateToken(bob);
        eveToken = jwtTokenProvider.generateToken(eve);

        // Generate and persist authentic ML-DSA-65 identity key for Alice
        aliceDsaKey = signatureService.generateKeyPair();
        String aliceIkB64 = Base64.getEncoder().encodeToString(aliceDsaKey.publicKey());

        UserKeyBundleEntity bundle = new UserKeyBundleEntity(
                alice,
                aliceIkB64,
                "ML-DSA-65",
                "sampleSpkB64",
                "ML-KEM-768",
                "sampleSpkSigB64",
                1
        );
        keyBundleRepository.save(bundle);
    }

    @Test
    @DisplayName("Lab Attack 1: Replay Attack — Submitting identical messageId must be rejected with HTTP 400 and audited")
    void testReplayAttackRejectedAndAudited() throws Exception {
        String msgId = "lab-replay-" + UUID.randomUUID();
        long seq = 1L;
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);
        String ciphertext = Base64.getEncoder().encodeToString("CiphertextA".getBytes(StandardCharsets.UTF_8));

        String payloadToSign = msgId + ":" + seq + ":" + nonce + ":" + ciphertext;
        byte[] sig = signatureService.sign(payloadToSign.getBytes(StandardCharsets.UTF_8), aliceDsaKey.privateKey());
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        SendMessageRequest request = new SendMessageRequest(
                "bob",
                msgId,
                ciphertext,
                nonce,
                null,
                sigB64,
                seq
        );

        // 1. Initial legitimate transmission succeeds
        mockMvc.perform(post("/api/v1/messages")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        // 2. Adversary replays identical frame -> must be blocked
        mockMvc.perform(post("/api/v1/messages")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("replay attack")));

        // 3. Verify server audit trail recorded REPLAY_ATTACK_DETECTED
        List<AuditLogEntity> replayAudits = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(AuditEventType.REPLAY_ATTACK_DETECTED);
        assertFalse(replayAudits.isEmpty(), "Server must record immutable REPLAY_ATTACK_DETECTED audit log");
    }

    @Test
    @DisplayName("Lab Attack 2: Bad Signature — Modified payload must fail ML-DSA-65 verification with HTTP 400 and audit")
    void testBadSignatureRejectedAndAudited() throws Exception {
        String msgId = "lab-badsig-" + UUID.randomUUID();
        long seq = 2L;
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);
        String ciphertext = Base64.getEncoder().encodeToString("LegitimateText".getBytes(StandardCharsets.UTF_8));

        // Sign legitimate payload
        String legitimatePayload = msgId + ":" + seq + ":" + nonce + ":" + ciphertext;
        byte[] sig = signatureService.sign(legitimatePayload.getBytes(StandardCharsets.UTF_8), aliceDsaKey.privateKey());
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        // Adversary alters ciphertext to "TamperedText" while keeping original signature
        String tamperedCiphertext = Base64.getEncoder().encodeToString("TamperedText".getBytes(StandardCharsets.UTF_8));

        SendMessageRequest tamperedRequest = new SendMessageRequest(
                "bob",
                msgId,
                tamperedCiphertext,
                nonce,
                null,
                sigB64,
                seq
        );

        mockMvc.perform(post("/api/v1/messages")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(tamperedRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("Invalid message signature")));

        List<AuditLogEntity> sigAudits = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(AuditEventType.SIGNATURE_VERIFICATION_FAILED);
        assertFalse(sigAudits.isEmpty(), "Server must record SIGNATURE_VERIFICATION_FAILED audit log");
    }

    @Test
    @DisplayName("Lab Attack 3: IDOR — Unauthorized user 'eve' must be rejected with HTTP 403 when requesting Alice's attachment")
    void testIdorAttachmentDownloadForbidden() throws Exception {
        // Alice uploads an encrypted file for Bob
        byte[] fileBytes = "ENCRYPTED_PAYLOAD_CHUNK".getBytes(StandardCharsets.UTF_8);
        MockMultipartFile file = new MockMultipartFile("file", "secret.enc", "application/octet-stream", fileBytes);

        String uploadJson = mockMvc.perform(multipart("/api/v1/attachments/upload")
                        .file(file)
                        .param("recipientUsername", "bob")
                        .param("encryptedFilename", "secret.enc")
                        .param("nonce", Base64.getEncoder().encodeToString(new byte[12]))
                        .param("mimeType", "application/pdf")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        String fileId = objectMapper.readTree(uploadJson).path("data").path("fileId").asText();

        // 1. Authorized recipient 'bob' CAN download
        mockMvc.perform(get("/api/v1/attachments/" + fileId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken))
                .andExpect(status().isOk());

        // 2. Unauthorized attacker 'eve' CANNOT download -> HTTP 403
        mockMvc.perform(get("/api/v1/attachments/" + fileId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + eveToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Lab Attack 4: IDOR Stream — Unauthorized user 'eve' must be rejected with HTTP 403 on streaming endpoint")
    void testIdorAttachmentStreamForbidden() throws Exception {
        byte[] fileBytes = "STREAMING_CIPHERTEXT".getBytes(StandardCharsets.UTF_8);
        MockMultipartFile file = new MockMultipartFile("file", "payroll.enc", "application/octet-stream", fileBytes);

        String uploadJson = mockMvc.perform(multipart("/api/v1/attachments/upload")
                        .file(file)
                        .param("recipientUsername", "bob")
                        .param("encryptedFilename", "payroll.enc")
                        .param("nonce", Base64.getEncoder().encodeToString(new byte[12]))
                        .param("mimeType", "text/plain")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        String fileId = objectMapper.readTree(uploadJson).path("data").path("fileId").asText();

        // Attacker 'eve' attempts to stream ciphertext
        mockMvc.perform(get("/api/v1/attachments/" + fileId + "/stream")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + eveToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Lab Attack 5: IDOR Message Status — Unauthorized user 'eve' cannot modify status of Alice's message")
    void testIdorMessageStatusUpdateForbidden() throws Exception {
        String msgId = "lab-msg-" + UUID.randomUUID();
        long seq = 3L;
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);
        String ciphertext = Base64.getEncoder().encodeToString("Msg".getBytes(StandardCharsets.UTF_8));
        String payloadToSign = msgId + ":" + seq + ":" + nonce + ":" + ciphertext;
        byte[] sig = signatureService.sign(payloadToSign.getBytes(StandardCharsets.UTF_8), aliceDsaKey.privateKey());

        SendMessageRequest request = new SendMessageRequest(
                "bob",
                msgId,
                ciphertext,
                nonce,
                null,
                Base64.getEncoder().encodeToString(sig),
                seq
        );

        mockMvc.perform(post("/api/v1/messages")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        // Attacker 'eve' attempts to mark message as READ
        DeliveryReceiptRequest receipt = new DeliveryReceiptRequest("READ");
        mockMvc.perform(put("/api/v1/messages/" + msgId + "/status")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + eveToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(receipt)))
                .andExpect(status().isForbidden());
    }
}
