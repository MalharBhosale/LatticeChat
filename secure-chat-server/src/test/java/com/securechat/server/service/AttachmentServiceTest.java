package com.securechat.server.service;

import com.securechat.common.dto.UploadAttachmentResponse;
import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.repository.AttachmentRepository;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class AttachmentServiceTest {

    @Autowired
    private AttachmentService attachmentService;

    @Autowired
    private AttachmentRepository attachmentRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    private UserEntity alice;
    private UserEntity bob;
    private UserEntity charlie;

    @BeforeEach
    void setUp() {
        attachmentRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        alice = userRepository.save(new UserEntity("alice", "alice@latticechat.internal", "pw1", "Alice"));
        bob = userRepository.save(new UserEntity("bob", "bob@latticechat.internal", "pw2", "Bob"));
        charlie = userRepository.save(new UserEntity("charlie", "charlie@latticechat.internal", "pw3", "Charlie"));
    }

    @org.junit.jupiter.api.AfterEach
    void tearDown() {
        attachmentRepository.deleteAll();
        auditLogRepository.deleteAll();
        userRepository.deleteAll();
    }


    @Test
    @DisplayName("Should successfully store and load encrypted attachment")
    void testStoreAndLoadAttachment() throws IOException {
        byte[] fakeEncryptedBytes = "SimulatedAES256GCMCiphertextBlobWithTag".getBytes(StandardCharsets.UTF_8);
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);

        UploadAttachmentResponse response = attachmentService.storeAttachment(
                "alice", "bob", "secret_document.pdf.enc", "application/pdf", nonce, fakeEncryptedBytes
        );

        assertNotNull(response);
        assertNotNull(response.fileId());
        assertEquals(fakeEncryptedBytes.length, response.fileSizeBytes());

        // Uploader can download
        AttachmentService.AttachmentDownload uploaderDownload = attachmentService.loadAttachment(response.fileId(), "alice");
        assertArrayEquals(fakeEncryptedBytes, uploaderDownload.data());
        assertEquals("secret_document.pdf.enc", uploaderDownload.metadata().getEncryptedFilename());
        assertEquals("application/pdf", uploaderDownload.metadata().getMimeType());

        // Recipient can download
        AttachmentService.AttachmentDownload recipientDownload = attachmentService.loadAttachment(response.fileId(), "bob");
        assertArrayEquals(fakeEncryptedBytes, recipientDownload.data());

        // Verify audit log recorded
        boolean hasUploadAudit = auditLogRepository.findAll().stream()
                .anyMatch(a -> a.getEventType() == AuditEventType.ATTACHMENT_UPLOAD);
        assertTrue(hasUploadAudit);
    }

    @Test
    @DisplayName("Should reject unauthorized third-party attachment download with AccessDeniedException")
    void testUnauthorizedDownloadRejection() throws IOException {
        byte[] fakeBytes = "SecretData".getBytes(StandardCharsets.UTF_8);
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);

        UploadAttachmentResponse response = attachmentService.storeAttachment(
                "alice", "bob", "test.enc", "text/plain", nonce, fakeBytes
        );

        // Charlie (unauthorized third-party) attempts download
        assertThrows(AccessDeniedException.class, () ->
                attachmentService.loadAttachment(response.fileId(), "charlie")
        );
    }

    @Test
    @DisplayName("Should reject files exceeding 25 MB size limit")
    void testFileSizeLimitExceeded() {
        byte[] oversizedBytes = new byte[(int) (AttachmentService.MAX_FILE_SIZE_BYTES + 1024)];
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                attachmentService.storeAttachment("alice", "bob", "large.iso", "application/octet-stream", nonce, oversizedBytes)
        );
        assertTrue(ex.getMessage().contains("exceeds maximum limit"));
    }

    @Test
    @DisplayName("Should reject empty attachment bytes")
    void testEmptyAttachmentRejection() {
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);

        assertThrows(IllegalArgumentException.class, () ->
                attachmentService.storeAttachment("alice", "bob", "empty.bin", "application/octet-stream", nonce, new byte[0])
        );
    }

    @Test
    @DisplayName("Should sanitize filename and prevent path traversal")
    void testPathTraversalDefense() throws IOException {
        byte[] fakeBytes = "CleanBytes".getBytes(StandardCharsets.UTF_8);
        String nonce = Base64.getEncoder().encodeToString(new byte[12]);

        // Malicious directory traversal filename
        String maliciousName = "../../../../../../../etc/passwd";
        UploadAttachmentResponse response = attachmentService.storeAttachment(
                "alice", "bob", maliciousName, "text/plain", nonce, fakeBytes
        );

        assertNotNull(response.fileId());

        // File on disk must be inside uploads/ and named by UUID
        var entity = attachmentRepository.findByFileId(response.fileId()).orElseThrow();
        assertTrue(entity.getStoragePath().endsWith(response.fileId() + ".enc"));
        assertFalse(entity.getStoragePath().contains("passwd"));
    }
}
