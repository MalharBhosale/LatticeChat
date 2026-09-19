package com.securechat.server.controller;

import com.securechat.server.entity.UserEntity;
import com.securechat.server.repository.AttachmentRepository;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.UserRepository;
import com.securechat.server.security.JwtTokenProvider;
import org.junit.jupiter.api.AfterEach;
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
import org.springframework.test.web.servlet.MvcResult;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class StreamingAttachmentServerTest {

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

        alice = userRepository.save(new UserEntity("alice_stream", "alice_stream@latticechat.internal", "hash1", "Alice Stream"));
        bob = userRepository.save(new UserEntity("bob_stream", "bob_stream@latticechat.internal", "hash2", "Bob Stream"));
        eve = userRepository.save(new UserEntity("eve_stream", "eve_stream@latticechat.internal", "hash3", "Eve Stream"));

        aliceToken = jwtTokenProvider.generateToken(alice);
        bobToken = jwtTokenProvider.generateToken(bob);
        eveToken = jwtTokenProvider.generateToken(eve);
    }

    @AfterEach
    void tearDown() {
        attachmentRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Should upload and stream download attachment with access control and path sanitization")
    void testStreamingUploadAndDownload() throws Exception {
        byte[] payloadBytes = "LatticeChat Zero-Knowledge Streaming Encrypted Payload".getBytes();
        MockMultipartFile multipartFile = new MockMultipartFile(
                "file", "../../traversal_attack.pdf", "application/pdf", payloadBytes
        );

        String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]);

        // 1. Upload via /api/v1/attachments/stream
        String responseJson = mockMvc.perform(multipart("/api/v1/attachments/stream")
                        .file(multipartFile)
                        .param("recipientUsername", "bob_stream")
                        .param("encryptedFilename", "../../traversal_attack.pdf")
                        .param("nonce", nonceB64)
                        .param("mimeType", "application/pdf")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.fileId").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        String fileId = mapper.readTree(responseJson).path("data").path("fileId").asText();

        // Verify that path traversal in metadata was sanitized
        var entity = attachmentRepository.findByFileId(fileId).orElseThrow();
        assertEquals("traversal_attack.pdf", entity.getEncryptedFilename());

        // 2. Bob downloads via streaming endpoint /api/v1/attachments/{fileId}/stream
        MvcResult mvcResult = mockMvc.perform(get("/api/v1/attachments/" + fileId + "/stream")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken))
                .andExpect(status().isOk())
                .andExpect(header().string("X-LatticeChat-Nonce", nonceB64))
                .andExpect(header().string("X-LatticeChat-Mime", "application/pdf"))
                .andReturn();

        byte[] downloadedBytes = mvcResult.getResponse().getContentAsByteArray();
        assertArrayEquals(payloadBytes, downloadedBytes);

        // 3. Eve is rejected with 403 Forbidden
        mockMvc.perform(get("/api/v1/attachments/" + fileId + "/stream")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + eveToken))
                .andExpect(status().isForbidden());
    }
}
