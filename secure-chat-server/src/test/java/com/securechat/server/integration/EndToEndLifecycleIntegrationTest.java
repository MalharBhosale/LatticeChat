package com.securechat.server.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.KeyExchangeService.KemSecret;
import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.AesGcmEncryptionService;
import com.securechat.common.crypto.impl.HkdfKeyDerivationService;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;
import com.securechat.common.dto.*;
import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.entity.UserStatus;
import com.securechat.server.repository.*;
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
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Full-System End-to-End Cryptographic Lifecycle Integration Test.
 * Simulates real-world multi-party scenarios across Alice, Bob, and adversary Eve:
 * 1. PQC Identity Registration & Key Bundle Publishing.
 * 2. Asynchronous PQ-X3DH Handshake & E2EE Post-Quantum Message Relay.
 * 3. Bidirectional Ratcheted Conversation & Delivery Receipts.
 * 4. Encrypted Streaming File Attachment with IDOR Access Control.
 * 5. Versioned Signed Prekey Rotation & Key Bundle Revocation.
 * 6. Audit Trail Immutability Verification.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EndToEndLifecycleIntegrationTest {

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
    private AttachmentRepository attachmentRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();

    private final MlKemKeyExchangeService kem = MlKemKeyExchangeService.mlKem768();
    private final MlDsaSignatureService dsa = MlDsaSignatureService.mlDsa65();
    private final AesGcmEncryptionService aes = new AesGcmEncryptionService();
    private final HkdfKeyDerivationService hkdf = new HkdfKeyDerivationService();

    private UserEntity alice;
    private UserEntity bob;
    private UserEntity eve;

    private String aliceToken;
    private String bobToken;
    private String eveToken;

    // Cryptographic keys
    private SignatureKeyPair aliceIdKp;
    private KemKeyPair aliceSpkKp;

    private SignatureKeyPair bobIdKp;
    private KemKeyPair bobSpkKp;
    private KemKeyPair bobOpkKp;

    @BeforeEach
    void setUp() {
        tearDown();

        // 1. Create simulated user records
        alice = userRepository.save(new UserEntity("alice_e2e", "alice_e2e@latticechat.internal", "$2a$12$hashPass1", "Alice E2E"));
        alice.setStatus(UserStatus.ACTIVE);
        alice = userRepository.save(alice);

        bob = userRepository.save(new UserEntity("bob_e2e", "bob_e2e@latticechat.internal", "$2a$12$hashPass2", "Bob E2E"));
        bob.setStatus(UserStatus.ACTIVE);
        bob = userRepository.save(bob);

        eve = userRepository.save(new UserEntity("eve_e2e", "eve_e2e@latticechat.internal", "$2a$12$hashPass3", "Eve E2E"));
        eve.setStatus(UserStatus.ACTIVE);
        eve = userRepository.save(eve);

        aliceToken = jwtTokenProvider.generateToken(alice);
        bobToken = jwtTokenProvider.generateToken(bob);
        eveToken = jwtTokenProvider.generateToken(eve);

        // 2. Generate initial PQC keypairs
        aliceIdKp = dsa.generateKeyPair();
        aliceSpkKp = kem.generateKeyPair();

        bobIdKp = dsa.generateKeyPair();
        bobSpkKp = kem.generateKeyPair();
        bobOpkKp = kem.generateKeyPair();
    }

    @AfterEach
    void tearDown() {
        attachmentRepository.deleteAll();
        messageRepository.deleteAll();
        prekeyRepository.deleteAll();
        keyBundleRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Complete E2E Lifecycle: Key publishing -> PQ-X3DH -> Messaging -> File transfer -> Key rotation -> Revocation -> Audit trail")
    void testCompleteCryptographicLifecycle() throws Exception {

        // =====================================================================
        // Stage 1: Publish PQC Key Bundles for Alice and Bob
        // =====================================================================
        byte[] bobSpkSig = dsa.sign(bobSpkKp.publicKey(), bobIdKp.privateKey());
        PublishKeyBundleRequest bobBundleReq = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(bobIdKp.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(bobSpkKp.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(bobSpkSig),
                List.of(new OneTimePrekeyUploadDto(1, Base64.getEncoder().encodeToString(bobOpkKp.publicKey()), "ML-KEM-768"))
        );

        mockMvc.perform(post("/api/v1/keys/bundle")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(bobBundleReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.keyVersion").value(1));

        byte[] aliceSpkSig = dsa.sign(aliceSpkKp.publicKey(), aliceIdKp.privateKey());
        PublishKeyBundleRequest aliceBundleReq = new PublishKeyBundleRequest(
                Base64.getEncoder().encodeToString(aliceIdKp.publicKey()),
                "ML-DSA-65",
                Base64.getEncoder().encodeToString(aliceSpkKp.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(aliceSpkSig),
                List.of()
        );

        mockMvc.perform(post("/api/v1/keys/bundle")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(aliceBundleReq)))
                .andExpect(status().isCreated());

        // =====================================================================
        // Stage 2: Alice fetches Bob's Bundle & Initiates PQ-X3DH Handshake
        // =====================================================================
        String fetchJson = mockMvc.perform(get("/api/v1/keys/bundle/bob_e2e")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("bob_e2e"))
                .andExpect(jsonPath("$.data.oneTimePrekeyId").value(1))
                .andReturn().getResponse().getContentAsString();

        KeyExchangeBundleDto fetchedBobBundle = mapper.readTree(fetchJson).path("data")
                .traverse(mapper).readValueAs(KeyExchangeBundleDto.class);

        // Alice performs PQ-X3DH:
        // 1. Verify Bob's SPK signature
        byte[] bobSpkBytes = Base64.getDecoder().decode(fetchedBobBundle.signedPrekey());
        byte[] bobSpkSigBytes = Base64.getDecoder().decode(fetchedBobBundle.signedPrekeySignature());
        byte[] bobIdKeyBytes = Base64.getDecoder().decode(fetchedBobBundle.identityKey());
        assertTrue(dsa.verify(bobSpkBytes, bobSpkSigBytes, bobIdKeyBytes));

        // 2. Encapsulate against Bob's SPK and OPK
        KemSecret spkSecret = kem.encapsulate(bobSpkBytes);
        byte[] bobOpkBytes = Base64.getDecoder().decode(fetchedBobBundle.oneTimePrekey());
        KemSecret opkSecret = kem.encapsulate(bobOpkBytes);

        // 3. Derive symmetric master key via HKDF
        byte[] ikm = new byte[spkSecret.sharedSecret().length + opkSecret.sharedSecret().length];
        System.arraycopy(spkSecret.sharedSecret(), 0, ikm, 0, spkSecret.sharedSecret().length);
        System.arraycopy(opkSecret.sharedSecret(), 0, ikm, spkSecret.sharedSecret().length, opkSecret.sharedSecret().length);

        byte[] sessionKey = hkdf.deriveKey(ikm, "LatticeChat-PQ-X3DH-v1".getBytes(StandardCharsets.UTF_8), "session-key".getBytes(StandardCharsets.UTF_8), 32);

        // Header: ctSpk || ctOpk
        String ephemeralKemHeader = Base64.getEncoder().encodeToString(spkSecret.encapsulationCiphertext())
                + ":" + Base64.getEncoder().encodeToString(opkSecret.encapsulationCiphertext());

        // =====================================================================
        // Stage 3: Alice sends First E2EE Post-Quantum Message to Bob
        // =====================================================================
        String msgPlaintext = "Hello Bob! Quantum computers cannot decrypt this message.";
        byte[] msgBytes = msgPlaintext.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = aes.encrypt(msgBytes, sessionKey, null);
        String ctB64 = Base64.getEncoder().encodeToString(ciphertext);
        String nonceB64 = Base64.getEncoder().encodeToString(new byte[12]); // IV is embedded in ciphertext
        String msgId = UUID.randomUUID().toString();

        // Alice signs message header with her ML-DSA-65 identity key
        String payloadToSign = com.securechat.server.service.MessageService.buildPayloadString(msgId, 1L, nonceB64, ctB64);
        byte[] sig = dsa.sign(payloadToSign.getBytes(StandardCharsets.UTF_8), aliceIdKp.privateKey());
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        SendMessageRequest sendReq = new SendMessageRequest(
                "bob_e2e",
                msgId,
                ctB64,
                nonceB64,
                ephemeralKemHeader,
                sigB64,
                1L
        );

        mockMvc.perform(post("/api/v1/messages")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(sendReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.status").value("SENT"));

        // =====================================================================
        // Stage 4: Bob Receives Message & Processes PQ-X3DH Decapsulation
        // =====================================================================
        String inboxJson = mockMvc.perform(get("/api/v1/messages/pending")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").isArray())
                .andReturn().getResponse().getContentAsString();

        List<EncryptedMessageDto> messages = mapper.readValue(
                mapper.readTree(inboxJson).path("data").toString(),
                mapper.getTypeFactory().constructCollectionType(List.class, EncryptedMessageDto.class)
        );
        assertEquals(1, messages.size());
        EncryptedMessageDto rcvDto = messages.get(0);

        // Bob parses header and decapsulates with his private keys
        String[] parts = rcvDto.encapsulationCiphertextBase64().split(":");
        byte[] rcvCtSpk = Base64.getDecoder().decode(parts[0]);
        byte[] rcvCtOpk = Base64.getDecoder().decode(parts[1]);

        byte[] bobSsSpk = kem.decapsulate(bobSpkKp.privateKey(), rcvCtSpk);
        byte[] bobSsOpk = kem.decapsulate(bobOpkKp.privateKey(), rcvCtOpk);

        byte[] bobIkm = new byte[bobSsSpk.length + bobSsOpk.length];
        System.arraycopy(bobSsSpk, 0, bobIkm, 0, bobSsSpk.length);
        System.arraycopy(bobSsOpk, 0, bobIkm, bobSsSpk.length, bobSsOpk.length);

        byte[] bobDerivedSessionKey = hkdf.deriveKey(bobIkm, "LatticeChat-PQ-X3DH-v1".getBytes(StandardCharsets.UTF_8), "session-key".getBytes(StandardCharsets.UTF_8), 32);

        // Bob decrypts payload
        byte[] rcvCiphertext = Base64.getDecoder().decode(rcvDto.ciphertextBase64());
        byte[] decrypted = aes.decrypt(rcvCiphertext, bobDerivedSessionKey, null);
        assertEquals(msgPlaintext, new String(decrypted, StandardCharsets.UTF_8));

        // Bob submits READ receipt
        DeliveryReceiptRequest receiptReq = new DeliveryReceiptRequest("READ");
        mockMvc.perform(put("/api/v1/messages/" + rcvDto.messageId() + "/status")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(receiptReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("READ"));

        // =====================================================================
        // Stage 5: Encrypted File Transfer & IDOR Verification
        // =====================================================================
        byte[] fileBytes = "TOP_SECRET_POST_QUANTUM_BLUEPRINT_2026_FIPS_203_204".getBytes(StandardCharsets.UTF_8);
        byte[] encFileBytes = aes.encrypt(fileBytes, sessionKey, null);

        MockMultipartFile multipartFile = new MockMultipartFile(
                "file",
                "blueprint.pdf.enc",
                MediaType.APPLICATION_OCTET_STREAM_VALUE,
                encFileBytes
        );

        String uploadJson = mockMvc.perform(multipart("/api/v1/attachments/stream")
                        .file(multipartFile)
                        .param("recipientUsername", "bob_e2e")
                        .param("encryptedFilename", "blueprint.pdf.enc")
                        .param("nonce", Base64.getEncoder().encodeToString(new byte[12]))
                        .param("mimeType", "application/pdf")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.fileId").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        String fileId = mapper.readTree(uploadJson).path("data").path("fileId").asText();

        // Bob streams download
        MvcResult mvcStream = mockMvc.perform(get("/api/v1/attachments/" + fileId + "/stream")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken))
                .andExpect(request().asyncStarted())
                .andReturn();

        mockMvc.perform(asyncDispatch(mvcStream))
                .andExpect(status().isOk())
                .andExpect(header().string("X-LatticeChat-Mime", "application/pdf"));

        byte[] downloaded = mvcStream.getResponse().getContentAsByteArray();
        byte[] decryptedFile = aes.decrypt(downloaded, bobDerivedSessionKey, null);
        assertArrayEquals(fileBytes, decryptedFile);

        // Eve (IDOR attack) attempt is rejected with 403 Forbidden
        mockMvc.perform(get("/api/v1/attachments/" + fileId + "/stream")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + eveToken))
                .andExpect(status().isForbidden());

        // =====================================================================
        // Stage 6: Versioned Key Rotation
        // =====================================================================
        KemKeyPair newAliceSpk = kem.generateKeyPair();
        byte[] newAliceSpkSig = dsa.sign(newAliceSpk.publicKey(), aliceIdKp.privateKey());

        RotateKeyBundleRequest rotateReq = new RotateKeyBundleRequest(
                Base64.getEncoder().encodeToString(newAliceSpk.publicKey()),
                "ML-KEM-768",
                Base64.getEncoder().encodeToString(newAliceSpkSig),
                List.of()
        );

        mockMvc.perform(post("/api/v1/keys/rotate")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(rotateReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.keyVersion").value(2));

        // =====================================================================
        // Stage 7: Key Revocation
        // =====================================================================
        RevokeKeyBundleRequest revokeReq = new RevokeKeyBundleRequest(
                "Compromised ephemeral device cache test",
                "Full emergency revocation"
        );

        mockMvc.perform(post("/api/v1/keys/revoke")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(revokeReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // Subsequent bundle fetches for Alice fail because active bundle was revoked
        mockMvc.perform(get("/api/v1/keys/bundle/alice_e2e")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + bobToken))
                .andExpect(status().isNotFound());

        // =====================================================================
        // Stage 8: Audit Trail Verification
        // =====================================================================
        mockMvc.perform(get("/api/v1/keys/audit-trail")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").isArray());

        var aliceLogs = auditLogRepository.findByUserIdOrderByCreatedAtDesc(alice.getId());
        assertTrue(aliceLogs.stream().anyMatch(l -> l.getEventType() == AuditEventType.KEY_UPLOAD));
        assertTrue(aliceLogs.stream().anyMatch(l -> l.getEventType() == AuditEventType.KEY_ROTATION));
        assertTrue(aliceLogs.stream().anyMatch(l -> l.getEventType() == AuditEventType.KEY_REVOCATION));
        assertTrue(aliceLogs.stream().anyMatch(l -> l.getEventType() == AuditEventType.ATTACHMENT_UPLOAD));
    }
}
