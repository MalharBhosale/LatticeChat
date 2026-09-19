package com.securechat.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.dto.OneTimePrekeyUploadDto;
import com.securechat.common.dto.PublishKeyBundleRequest;
import com.securechat.common.dto.RevokeKeyBundleRequest;
import com.securechat.common.dto.RotateKeyBundleRequest;
import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.OneTimePrekeyRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
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
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class KeyRevocationAndAuditTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserKeyBundleRepository keyBundleRepository;

    @Autowired
    private OneTimePrekeyRepository prekeyRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private ObjectMapper objectMapper;

    private final MlDsaSignatureService dsaService = new MlDsaSignatureService();
    private final MlKemKeyExchangeService kemService = new MlKemKeyExchangeService();

    private UserEntity alice;
    private String aliceToken;
    private SignatureKeyPair aliceIdPair;

    @BeforeEach
    void setUp() {
        tearDown();

        alice = userRepository.save(new UserEntity("alice_rev", "alice_rev@latticechat.internal", "pw", "Alice Rev"));
        aliceToken = jwtTokenProvider.generateToken(alice);
        aliceIdPair = dsaService.generateKeyPair();
    }

    @AfterEach
    void tearDown() {
        prekeyRepository.deleteAll();
        keyBundleRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Should publish bundle, rotate prekey, revoke bundle, and query complete audit trail")
    void testKeyRevocationAndAuditTrail() throws Exception {
        // 1. Publish initial key bundle (v1) with 2 OPKs
        KemKeyPair spk1 = kemService.generateKeyPair();
        byte[] sig1 = dsaService.sign(spk1.publicKey(), aliceIdPair.privateKey());

        KemKeyPair opk1 = kemService.generateKeyPair();
        KemKeyPair opk2 = kemService.generateKeyPair();

        PublishKeyBundleRequest initialReq = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(aliceIdPair.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(spk1.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig1),
                List.of(
                        new OneTimePrekeyUploadDto(1, Base64.getEncoder().encodeToString(opk1.publicKey()), "ML-KEM-768"),
                        new OneTimePrekeyUploadDto(2, Base64.getEncoder().encodeToString(opk2.publicKey()), "ML-KEM-768")
                )
        );

        mockMvc.perform(post("/api/v1/keys/bundle")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(initialReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.keyVersion").value(1));

        assertEquals(2, prekeyRepository.countByUserIdAndIsConsumedFalse(alice.getId()));

        // 2. Rotate prekey to v2
        KemKeyPair spk2 = kemService.generateKeyPair();
        byte[] sig2 = dsaService.sign(spk2.publicKey(), aliceIdPair.privateKey());
        RotateKeyBundleRequest rotReq = new RotateKeyBundleRequest(
                Base64.getEncoder().encodeToString(spk2.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig2),
                null
        );

        mockMvc.perform(post("/api/v1/keys/rotate")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(rotReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.keyVersion").value(2));

        // 3. Explicitly revoke key bundle
        RevokeKeyBundleRequest revokeReq = new RevokeKeyBundleRequest("SUSPECTED_DEVICE_THEFT", "Revoked from secondary device");

        mockMvc.perform(post("/api/v1/keys/revoke")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(revokeReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // Verify that active bundle is deactivated and OPKs are consumed
        assertTrue(keyBundleRepository.findByUserIdAndIsActiveTrue(alice.getId()).isEmpty(),
                "Active key bundle must be deactivated after revocation");
        assertEquals(0, prekeyRepository.countByUserIdAndIsConsumedFalse(alice.getId()),
                "All unconsumed one-time prekeys must be invalidated upon bundle revocation");

        // Verify fetching bundle for revoked user fails with 404
        mockMvc.perform(get("/api/v1/keys/bundle/alice_rev")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isNotFound());

        // 4. Query cryptographic audit trail via GET /api/v1/keys/audit-trail
        mockMvc.perform(get("/api/v1/keys/audit-trail")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data[0].eventType").value(AuditEventType.KEY_REVOCATION.name()))
                .andExpect(jsonPath("$.data[0].details").value(org.hamcrest.Matchers.containsString("SUSPECTED_DEVICE_THEFT")))
                .andExpect(jsonPath("$.data[1].eventType").value(AuditEventType.KEY_ROTATION.name()))
                .andExpect(jsonPath("$.data[2].eventType").value(AuditEventType.KEY_UPLOAD.name()));
    }
}
