package com.securechat.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.dto.PublishKeyBundleRequest;
import com.securechat.common.dto.RotateKeyBundleRequest;
import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.OneTimePrekeyRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
import com.securechat.server.repository.UserRepository;
import com.securechat.server.security.JwtTokenProvider;
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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class KeyRotationTest {

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
        prekeyRepository.deleteAll();
        keyBundleRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        alice = userRepository.save(new UserEntity("alice_rot", "alice_rot@latticechat.internal", "pw", "Alice Rot"));
        aliceToken = jwtTokenProvider.generateToken(alice);

        // Generate permanent identity key (ML-DSA-65)
        aliceIdPair = dsaService.generateKeyPair();
    }

    @Test
    @DisplayName("Should successfully publish initial bundle (v1) and then rotate signed prekey (v2, v3)")
    void testKeyRotationVersionProgression() throws Exception {
        // 1. Initial bundle publication (v1)
        KemKeyPair spk1 = kemService.generateKeyPair();
        byte[] sig1 = dsaService.sign(spk1.publicKey(), aliceIdPair.privateKey());

        PublishKeyBundleRequest initialReq = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(aliceIdPair.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(spk1.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig1),
                null
        );

        mockMvc.perform(post("/api/v1/keys/bundle")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(initialReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.keyVersion").value(1));

        // 2. Rotate signed prekey to v2
        KemKeyPair spk2 = kemService.generateKeyPair();
        byte[] sig2 = dsaService.sign(spk2.publicKey(), aliceIdPair.privateKey());

        RotateKeyBundleRequest rot1 = new RotateKeyBundleRequest(
                Base64.getEncoder().encodeToString(spk2.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig2),
                null
        );

        mockMvc.perform(post("/api/v1/keys/rotate")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(rot1)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.keyVersion").value(2))
                .andExpect(jsonPath("$.data.kemPublicKeyBase64").value(Base64.getEncoder().encodeToString(spk2.publicKey())));


        // 3. Rotate signed prekey again to v3
        KemKeyPair spk3 = kemService.generateKeyPair();
        byte[] sig3 = dsaService.sign(spk3.publicKey(), aliceIdPair.privateKey());

        RotateKeyBundleRequest rot2 = new RotateKeyBundleRequest(
                Base64.getEncoder().encodeToString(spk3.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig3),
                null
        );

        mockMvc.perform(post("/api/v1/keys/rotate")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(rot2)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.keyVersion").value(3));

        // 4. Verify audit log captures KEY_ROTATION events
        long rotationCount = auditLogRepository.findAll().stream()
                .filter(a -> a.getEventType() == AuditEventType.KEY_ROTATION)
                .count();
        assertTrue(rotationCount >= 2);
    }

    @Test
    @DisplayName("POST /api/v1/keys/rotate: Should reject invalid prekey signature with 400 Bad Request")
    void testRotateInvalidSignature() throws Exception {
        // Initial publication
        KemKeyPair spk1 = kemService.generateKeyPair();
        byte[] sig1 = dsaService.sign(spk1.publicKey(), aliceIdPair.privateKey());
        PublishKeyBundleRequest initialReq = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(aliceIdPair.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(spk1.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig1),
                null
        );
        mockMvc.perform(post("/api/v1/keys/bundle")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(initialReq)))
                .andExpect(status().isCreated());

        // Attempt rotation with bad signature
        KemKeyPair spk2 = kemService.generateKeyPair();
        byte[] tamperedSig = new byte[3309]; // dummy zeros

        RotateKeyBundleRequest badRot = new RotateKeyBundleRequest(
                Base64.getEncoder().encodeToString(spk2.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(tamperedSig),
                null
        );

        mockMvc.perform(post("/api/v1/keys/rotate")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(badRot)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
    }
}
