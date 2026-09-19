package com.securechat.server.service;

import com.securechat.common.dto.EncryptedAttachmentDto;
import com.securechat.common.dto.UploadAttachmentResponse;
import com.securechat.server.entity.AttachmentEntity;
import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.AuditLogEntity;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.exception.ResourceNotFoundException;
import com.securechat.server.repository.AttachmentRepository;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

/**
 * Service managing zero-knowledge encrypted file attachment uploads and downloads.
 * Guarantees zero-knowledge storage, enforces 25 MB file size ceilings, and
 * prevents path traversal by generating random UUID disk filenames in a quarantined directory.
 */
@Service
public class AttachmentService {

    private static final Logger log = LoggerFactory.getLogger(AttachmentService.class);
    public static final long MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024L; // 25 MB limit

    private final AttachmentRepository attachmentRepository;
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final Path uploadDirectory;

    public AttachmentService(AttachmentRepository attachmentRepository,
                             UserRepository userRepository,
                             AuditLogRepository auditLogRepository,
                             @Value("${latticechat.upload.dir:uploads}") String uploadDir) {
        this.attachmentRepository = attachmentRepository;
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.uploadDirectory = Paths.get(uploadDir).toAbsolutePath().normalize();

        try {
            Files.createDirectories(this.uploadDirectory);
        } catch (IOException e) {
            log.error("Failed to initialize upload directory: {}", this.uploadDirectory, e);
        }
    }

    /**
     * Stores an encrypted attachment blob.
     * Prevents directory traversal attacks by persisting purely via random UUIDs.
     */
    @Transactional
    public UploadAttachmentResponse storeAttachment(String uploaderUsername,
                                                    String recipientUsername,
                                                    String encryptedFilename,
                                                    String mimeType,
                                                    String nonce,
                                                    byte[] encryptedBytes) throws IOException {
        if (encryptedBytes == null || encryptedBytes.length == 0) {
            throw new IllegalArgumentException("File content cannot be empty");
        }
        if (encryptedBytes.length > MAX_FILE_SIZE_BYTES) {
            throw new IllegalArgumentException("File size (" + encryptedBytes.length + " bytes) exceeds maximum limit of 25 MB");
        }
        if (nonce == null || nonce.isBlank()) {
            throw new IllegalArgumentException("Cryptographic nonce is required");
        }

        UserEntity uploader = userRepository.findByUsername(uploaderUsername)
                .orElseThrow(() -> new ResourceNotFoundException("Uploader '" + uploaderUsername + "' not found"));
        UserEntity recipient = userRepository.findByUsername(recipientUsername)
                .orElseThrow(() -> new ResourceNotFoundException("Recipient '" + recipientUsername + "' not found"));

        String fileId = UUID.randomUUID().toString();
        // Secure quarantined storage filename with path traversal defense
        String safeDiskName = fileId + ".enc";
        Path targetPath = com.securechat.common.util.SafePathUtils.resolveSafePath(this.uploadDirectory, safeDiskName);

        Files.write(targetPath, encryptedBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        String safeClientFilename = com.securechat.common.util.SafePathUtils.sanitizeFilename(encryptedFilename);

        AttachmentEntity entity = new AttachmentEntity(
                fileId,
                uploader,
                recipient,
                safeClientFilename,
                mimeType != null ? mimeType : "application/octet-stream",
                (long) encryptedBytes.length,
                targetPath.toString(),
                nonce
        );

        AttachmentEntity saved = attachmentRepository.save(entity);
        recordAuditLog(uploader, AuditEventType.ATTACHMENT_UPLOAD,
                "Uploaded encrypted attachment [" + fileId + "] to recipient: " + recipientUsername + " (" + encryptedBytes.length + " bytes)");

        log.info("Stored encrypted attachment [{}] from '{}' to '{}' ({} bytes)", fileId, uploaderUsername, recipientUsername, encryptedBytes.length);
        return new UploadAttachmentResponse(saved.getFileId(), saved.getFileSizeBytes(), saved.getCreatedAt());
    }

    /**
     * Stores an encrypted attachment blob via streaming InputStream.
     * Prevents heap memory exhaustion for multi-megabyte files.
     */
    @Transactional
    public UploadAttachmentResponse storeAttachmentStream(String uploaderUsername,
                                                          String recipientUsername,
                                                          String encryptedFilename,
                                                          String mimeType,
                                                          String nonce,
                                                          java.io.InputStream inputStream) throws IOException {
        if (nonce == null || nonce.isBlank()) {
            throw new IllegalArgumentException("Cryptographic nonce is required");
        }

        UserEntity uploader = userRepository.findByUsername(uploaderUsername)
                .orElseThrow(() -> new ResourceNotFoundException("Uploader '" + uploaderUsername + "' not found"));
        UserEntity recipient = userRepository.findByUsername(recipientUsername)
                .orElseThrow(() -> new ResourceNotFoundException("Recipient '" + recipientUsername + "' not found"));

        String fileId = UUID.randomUUID().toString();
        String safeDiskName = fileId + ".enc";
        Path targetPath = com.securechat.common.util.SafePathUtils.resolveSafePath(this.uploadDirectory, safeDiskName);

        long bytesWritten = 0;
        try (java.io.OutputStream out = Files.newOutputStream(targetPath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            byte[] buf = new byte[64 * 1024];
            int read;
            while ((read = inputStream.read(buf)) != -1) {
                bytesWritten += read;
                if (bytesWritten > MAX_FILE_SIZE_BYTES) {
                    out.close();
                    Files.deleteIfExists(targetPath);
                    throw new IllegalArgumentException("File size exceeds maximum limit of 25 MB");
                }
                out.write(buf, 0, read);
            }
        }

        if (bytesWritten == 0) {
            Files.deleteIfExists(targetPath);
            throw new IllegalArgumentException("File content cannot be empty");
        }

        String safeClientFilename = com.securechat.common.util.SafePathUtils.sanitizeFilename(encryptedFilename);

        AttachmentEntity entity = new AttachmentEntity(
                fileId,
                uploader,
                recipient,
                safeClientFilename,
                mimeType != null ? mimeType : "application/octet-stream",
                bytesWritten,
                targetPath.toString(),
                nonce
        );

        AttachmentEntity saved = attachmentRepository.save(entity);
        recordAuditLog(uploader, AuditEventType.ATTACHMENT_UPLOAD,
                "Uploaded streaming encrypted attachment [" + fileId + "] to recipient: " + recipientUsername + " (" + bytesWritten + " bytes)");

        log.info("Stored streaming encrypted attachment [{}] from '{}' to '{}' ({} bytes)", fileId, uploaderUsername, recipientUsername, bytesWritten);
        return new UploadAttachmentResponse(saved.getFileId(), saved.getFileSizeBytes(), saved.getCreatedAt());
    }

    /**
     * Loads an encrypted file attachment blob with strict access control.
     * Only the uploader or recipient is authorized to download the ciphertext.
     */
    @Transactional(readOnly = true)
    public AttachmentDownload loadAttachment(String fileId, String requestingUsername) throws IOException {
        AttachmentEntity attachment = attachmentRepository.findByFileId(fileId)
                .orElseThrow(() -> new ResourceNotFoundException("Attachment [" + fileId + "] not found"));

        boolean isUploader = attachment.getUploader().getUsername().equalsIgnoreCase(requestingUsername);
        boolean isRecipient = attachment.getRecipient().getUsername().equalsIgnoreCase(requestingUsername);

        if (!isUploader && !isRecipient) {
            log.warn("Unauthorized attachment download attempt for [{}] by user '{}'", fileId, requestingUsername);
            throw new AccessDeniedException("You are not authorized to download this attachment");
        }

        Path filePath = Paths.get(attachment.getStoragePath());
        com.securechat.common.util.SafePathUtils.assertSafePath(this.uploadDirectory, filePath);

        if (!Files.exists(filePath)) {
            throw new ResourceNotFoundException("Physical file not found on server storage for attachment [" + fileId + "]");
        }

        byte[] fileBytes = Files.readAllBytes(filePath);

        recordAuditLog(isUploader ? attachment.getUploader() : attachment.getRecipient(),
                AuditEventType.ATTACHMENT_DOWNLOAD,
                "Downloaded encrypted attachment [" + fileId + "] by user: " + requestingUsername);

        return new AttachmentDownload(attachment, fileBytes);
    }

    /**
     * Streams an encrypted file attachment directly from quarantined disk storage.
     */
    @Transactional(readOnly = true)
    public StreamingAttachmentDownload loadAttachmentStream(String fileId, String requestingUsername) throws IOException {
        AttachmentEntity attachment = attachmentRepository.findByFileId(fileId)
                .orElseThrow(() -> new ResourceNotFoundException("Attachment [" + fileId + "] not found"));

        boolean isUploader = attachment.getUploader().getUsername().equalsIgnoreCase(requestingUsername);
        boolean isRecipient = attachment.getRecipient().getUsername().equalsIgnoreCase(requestingUsername);

        if (!isUploader && !isRecipient) {
            log.warn("Unauthorized attachment stream attempt for [{}] by user '{}'", fileId, requestingUsername);
            throw new AccessDeniedException("You are not authorized to download this attachment");
        }

        Path filePath = Paths.get(attachment.getStoragePath());
        com.securechat.common.util.SafePathUtils.assertSafePath(this.uploadDirectory, filePath);

        if (!Files.exists(filePath)) {
            throw new ResourceNotFoundException("Physical file not found on server storage for attachment [" + fileId + "]");
        }

        recordAuditLog(isUploader ? attachment.getUploader() : attachment.getRecipient(),
                AuditEventType.ATTACHMENT_DOWNLOAD,
                "Streamed encrypted attachment [" + fileId + "] by user: " + requestingUsername);

        java.io.InputStream stream = Files.newInputStream(filePath, StandardOpenOption.READ);
        long size = Files.size(filePath);
        return new StreamingAttachmentDownload(attachment, stream, size);
    }

    public EncryptedAttachmentDto mapToDto(AttachmentEntity entity) {
        return new EncryptedAttachmentDto(
                entity.getId(),
                entity.getFileId(),
                entity.getUploader().getId(),
                entity.getUploader().getUsername(),
                entity.getRecipient().getId(),
                entity.getRecipient().getUsername(),
                entity.getEncryptedFilename(),
                entity.getMimeType(),
                entity.getFileSizeBytes(),
                entity.getNonce(),
                entity.getCreatedAt()
        );
    }

    private void recordAuditLog(UserEntity user, AuditEventType eventType, String details) {
        try {
            auditLogRepository.save(new AuditLogEntity(user, eventType, "127.0.0.1", details));
        } catch (Exception e) {
            log.error("Failed to write audit log for event {}: {}", eventType, e.getMessage());
        }
    }

    public record AttachmentDownload(AttachmentEntity metadata, byte[] data) {}
    public record StreamingAttachmentDownload(AttachmentEntity metadata, java.io.InputStream stream, long fileLength) {}
}
