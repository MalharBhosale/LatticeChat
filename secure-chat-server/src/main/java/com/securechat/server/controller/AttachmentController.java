package com.securechat.server.controller;

import com.securechat.common.dto.ApiResponse;
import com.securechat.common.dto.EncryptedAttachmentDto;
import com.securechat.common.dto.UploadAttachmentResponse;
import com.securechat.server.service.AttachmentService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

/**
 * REST controller for zero-knowledge end-to-end encrypted file attachment transfer.
 * All endpoints require valid JWT Bearer authentication.
 */
@RestController
@RequestMapping("/api/v1/attachments")
public class AttachmentController {

    private final AttachmentService attachmentService;

    public AttachmentController(AttachmentService attachmentService) {
        this.attachmentService = attachmentService;
    }

    /**
     * Uploads an end-to-end encrypted file attachment blob.
     */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponse<UploadAttachmentResponse>> uploadAttachment(
            @RequestParam("file") MultipartFile file,
            @RequestParam("recipientUsername") String recipientUsername,
            @RequestParam(value = "encryptedFilename", required = false) String encryptedFilename,
            @RequestParam("nonce") String nonce,
            @RequestParam(value = "mimeType", required = false) String mimeType,
            Authentication authentication) throws IOException {

        String uploaderUsername = authentication.getName();
        byte[] bytes = file.getBytes();
        String originalName = (encryptedFilename != null && !encryptedFilename.isBlank())
                ? encryptedFilename
                : file.getOriginalFilename();

        String effectiveMime = (mimeType != null && !mimeType.isBlank())
                ? mimeType
                : file.getContentType();

        UploadAttachmentResponse response = attachmentService.storeAttachment(
                uploaderUsername,
                recipientUsername,
                originalName,
                effectiveMime,
                nonce,
                bytes
        );

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Attachment uploaded successfully", response));
    }

    /**
     * Downloads an encrypted file attachment blob.
     * Enforces strict authorization (only uploader or intended recipient).
     */
    @GetMapping("/{fileId}")
    public ResponseEntity<byte[]> downloadAttachment(
            @PathVariable("fileId") String fileId,
            Authentication authentication) throws IOException {

        String requestingUsername = authentication.getName();
        AttachmentService.AttachmentDownload download = attachmentService.loadAttachment(fileId, requestingUsername);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", download.metadata().getEncryptedFilename());
        headers.setContentLength(download.data().length);
        headers.set("X-LatticeChat-Nonce", download.metadata().getNonce());
        headers.set("X-LatticeChat-Mime", download.metadata().getMimeType());

        return new ResponseEntity<>(download.data(), headers, HttpStatus.OK);
    }

    /**
     * Retrieves metadata for an encrypted attachment.
     */
    @GetMapping("/{fileId}/meta")
    public ResponseEntity<ApiResponse<EncryptedAttachmentDto>> getAttachmentMetadata(
            @PathVariable("fileId") String fileId,
            Authentication authentication) throws IOException {

        String requestingUsername = authentication.getName();
        AttachmentService.AttachmentDownload download = attachmentService.loadAttachment(fileId, requestingUsername);
        EncryptedAttachmentDto dto = attachmentService.mapToDto(download.metadata());

        return ResponseEntity.ok(ApiResponse.ok("Attachment metadata retrieved", dto));
    }
}
