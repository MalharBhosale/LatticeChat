package com.securechat.server.controller;

import com.securechat.server.entity.UserEntity;
import com.securechat.server.repository.AttachmentRepository;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.UserRepository;
import com.securechat.server.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AttachmentControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AttachmentRepository attachmentRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private UserEntity alice;
    private UserEntity bob;
    private UserEntity eve;

    private String aliceToken;
    private String bobToken;
    private String eveToken;

    @BeforeEach
    void setUp() {
        attachmentRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        alice = userRepository.save(new UserEntity("alice_att", "alice_att@latticechat.internal", "hash1", "Alice Att"));
        bob = userRepository.save(new UserEntity("bob_att", "bob_att@latticechat.internal", "hash2", "Bob Att"));
        eve = userRepository.save(new UserEntity("eve_att", "eve_att@latticechat.internal", "hash3", "Eve Att"));

        aliceToken = jwtTokenProvider.generateToken(alice);
        bobToken = jwtTokenProvider.generateToken(bob);
        eveToken = jwtTokenProvider.generateToken(eve);
    }

    @org.junit.jupiter.api.AfterEach
    void tearDown() {
        attachmentRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();
    }


    @Test
    @DisplayName("POST /api/v1/attachments/upload: Should upload attachment with valid token")
    void testUploadAttachmentSuccess() throws Exception {
        byte[] payload = "QuantumProtectedCiphertext".getBytes();
        MockMultipartFile file = new MockMultipartFile("file", "test.enc", "application/octet-stream", payload);
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);

        mockMvc.perform(multipart("/api/v1/attachments/upload")
                        .file(file)
                        .param("recipientUsername", "bob_att")
                        .param("encryptedFilename", "test.enc")
                        .param("nonce", nonce)
                        .param("mimeType", "application/octet-stream")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.fileId").isNotEmpty())
                .andExpect(jsonPath("$.data.fileSizeBytes").value(payload.length));
    }

    @Test
    @DisplayName("GET /api/v1/attachments/{fileId}: Recipient should download attachment; Eve should be forbidden")
    void testDownloadAttachmentAccessControl() throws Exception {
        byte[] payload = "QuantumEncryptedFilePayload".getBytes();
        MockMultipartFile file = new MockMultipartFile("file", "doc.enc", "application/octet-stream", payload);
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);

        String responseJson = mockMvc.perform(multipart("/api/v1/attachments/upload")
                        .file(file)
                        .param("recipientUsername", "bob_att")
                        .param("encryptedFilename", "doc.enc")
                        .param("nonce", nonce)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        com.fasterxml.jackson.databind.JsonNode root = new com.fasterxml.jackson.databind.ObjectMapper().readTree(responseJson);
        String fileId = root.path("data").path("fileId").asText();

        // Bob (recipient) downloads successfully
        mockMvc.perform(get("/api/v1/attachments/" + fileId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken))
                .andExpect(status().isOk())
                .andExpect(header().string("X-LatticeChat-Nonce", nonce));

        // Alice (uploader) downloads successfully
        mockMvc.perform(get("/api/v1/attachments/" + fileId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk());

        // Eve (unauthorized) download fails with 403 Forbidden
        mockMvc.perform(get("/api/v1/attachments/" + fileId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + eveToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /api/v1/attachments/{fileId}/meta: Should retrieve attachment metadata")
    void testGetAttachmentMetadata() throws Exception {
        byte[] payload = "MetaPayloadBytes".getBytes();
        MockMultipartFile file = new MockMultipartFile("file", "meta.enc", "application/octet-stream", payload);
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);

        String responseJson = mockMvc.perform(multipart("/api/v1/attachments/upload")
                        .file(file)
                        .param("recipientUsername", "bob_att")
                        .param("encryptedFilename", "meta.enc")
                        .param("nonce", nonce)
                        .param("mimeType", "text/plain")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        com.fasterxml.jackson.databind.JsonNode root = new com.fasterxml.jackson.databind.ObjectMapper().readTree(responseJson);
        String fileId = root.path("data").path("fileId").asText();

        mockMvc.perform(get("/api/v1/attachments/" + fileId + "/meta")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.fileId").value(fileId))
                .andExpect(jsonPath("$.data.uploaderUsername").value("alice_att"))
                .andExpect(jsonPath("$.data.recipientUsername").value("bob_att"))
                .andExpect(jsonPath("$.data.encryptedFilename").value("meta.enc"));
    }
}
