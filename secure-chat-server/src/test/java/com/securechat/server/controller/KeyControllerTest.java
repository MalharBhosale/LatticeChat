package com.securechat.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.dto.OneTimePrekeyUploadDto;
import com.securechat.common.dto.PublishKeyBundleRequest;
import com.securechat.common.dto.UploadPrekeysRequest;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.MessageRepository;
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
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class KeyControllerTest {

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
    private MessageRepository messageRepository;

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

    @BeforeEach
    void setUp() {
        messageRepository.deleteAll();
        prekeyRepository.deleteAll();
        keyBundleRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        alice = userRepository.save(new UserEntity("alice_ctrl", "alice_ctrl@latticechat.internal", "hash1", "Alice Ctrl"));
        bob = userRepository.save(new UserEntity("bob_ctrl", "bob_ctrl@latticechat.internal", "hash2", "Bob Ctrl"));

        aliceToken = jwtTokenProvider.generateToken(alice);
        bobToken = jwtTokenProvider.generateToken(bob);
    }

    @Test
    @DisplayName("POST /api/v1/keys/bundle: Should return 401 Unauthorized if token missing")
    void testPublishBundleUnauthenticated() throws Exception {
        mockMvc.perform(post("/api/v1/keys/bundle")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /api/v1/keys/bundle: Should publish valid PQC key bundle")
    void testPublishBundleSuccess() throws Exception {
        SignatureKeyPair idPair = dsaService.generateKeyPair();
        KemKeyPair prekeyPair = kemService.generateKeyPair();
        byte[] sig = dsaService.sign(prekeyPair.publicKey(), idPair.privateKey());

        KemKeyPair opk = kemService.generateKeyPair();

        PublishKeyBundleRequest request = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(idPair.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(prekeyPair.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig),
                List.of(new OneTimePrekeyUploadDto(1, Base64.getEncoder().encodeToString(opk.publicKey()), "ML-KEM-768"))
        );

        mockMvc.perform(post("/api/v1/keys/bundle")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.username").value("alice_ctrl"))
                .andExpect(jsonPath("$.data.keyVersion").value(1))
                .andExpect(jsonPath("$.data.dsaAlgorithm").value("ML-DSA-65"))
                .andExpect(jsonPath("$.data.kemAlgorithm").value("ML-KEM-768"));
    }

    @Test
    @DisplayName("POST /api/v1/keys/bundle: Should reject tampered signature with 400 Bad Request")
    void testPublishBundleBadSignature() throws Exception {
        SignatureKeyPair idPair = dsaService.generateKeyPair();
        KemKeyPair prekeyPair = kemService.generateKeyPair();

        // Corrupted signature
        byte[] fakeSig = new byte[3309];

        PublishKeyBundleRequest request = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(idPair.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(prekeyPair.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(fakeSig),
                null
        );

        mockMvc.perform(post("/api/v1/keys/bundle")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    @DisplayName("POST /api/v1/keys/prekeys & GET /api/v1/keys/prekeys/count: Should upload and check count")
    void testUploadPrekeysAndGetCount() throws Exception {
        // Initial count is 0, lowStock = true
        mockMvc.perform(get("/api/v1/keys/prekeys/count")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.remainingCount").value(0))
                .andExpect(jsonPath("$.data.lowStock").value(true));

        // Upload 2 prekeys
        KemKeyPair k1 = kemService.generateKeyPair();
        UploadPrekeysRequest upload = new UploadPrekeysRequest(List.of(
                new OneTimePrekeyUploadDto(1, Base64.getEncoder().encodeToString(k1.publicKey()), "ML-KEM-768"),
                new OneTimePrekeyUploadDto(2, Base64.getEncoder().encodeToString(k1.publicKey()), "ML-KEM-768")
        ));

        mockMvc.perform(post("/api/v1/keys/prekeys")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(upload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data").value(2));

        // Count should now be 2
        mockMvc.perform(get("/api/v1/keys/prekeys/count")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.remainingCount").value(2))
                .andExpect(jsonPath("$.data.lowStock").value(true));
    }

    @Test
    @DisplayName("GET /api/v1/keys/user/{username}: Should fetch recipient bundle and claim OPK")
    void testGetKeyExchangeBundle() throws Exception {
        // Alice publishes bundle with 1 OPK
        SignatureKeyPair idPair = dsaService.generateKeyPair();
        KemKeyPair prekeyPair = kemService.generateKeyPair();
        byte[] sig = dsaService.sign(prekeyPair.publicKey(), idPair.privateKey());
        KemKeyPair opk = kemService.generateKeyPair();

        PublishKeyBundleRequest request = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(idPair.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(prekeyPair.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(sig),
                List.of(new OneTimePrekeyUploadDto(555, Base64.getEncoder().encodeToString(opk.publicKey()), "ML-KEM-768"))
        );

        mockMvc.perform(post("/api/v1/keys/bundle")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        // Bob fetches Alice's bundle by username: claims OPK 555
        mockMvc.perform(get("/api/v1/keys/user/alice_ctrl")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.username").value("alice_ctrl"))
                .andExpect(jsonPath("$.data.oneTimePrekeyId").value(555))
                .andExpect(jsonPath("$.data.signedPrekey").isNotEmpty())
                .andExpect(jsonPath("$.data.identityKey").isNotEmpty());

        // Bob fetches Alice's bundle by user ID: OPKs are now exhausted, oneTimePrekey is null
        mockMvc.perform(get("/api/v1/keys/" + alice.getId())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.oneTimePrekeyId").doesNotExist())
                .andExpect(jsonPath("$.data.signedPrekey").isNotEmpty());
    }
}
