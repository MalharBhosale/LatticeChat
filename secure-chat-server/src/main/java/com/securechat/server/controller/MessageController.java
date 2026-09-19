package com.securechat.server.controller;

import com.securechat.common.dto.ApiResponse;
import com.securechat.common.dto.DeliveryReceiptRequest;
import com.securechat.common.dto.EncryptedMessageDto;
import com.securechat.common.dto.SendMessageRequest;
import com.securechat.server.entity.MessageStatus;
import com.securechat.server.service.MessageService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * REST controller for Zero-Knowledge End-to-End Encrypted message transmission,
 * pending queue retrieval, conversation history, and delivery receipts.
 * All endpoints require valid JWT Bearer authentication.
 */
@RestController
@RequestMapping("/api/v1/messages")
public class MessageController {

    private final MessageService messageService;

    public MessageController(MessageService messageService) {
        this.messageService = messageService;
    }

    /**
     * Transmits and relays an encrypted message.
     */
    @PostMapping
    public ResponseEntity<ApiResponse<EncryptedMessageDto>> sendMessage(
            @jakarta.validation.Valid @RequestBody SendMessageRequest request,
            Authentication authentication) {
        String senderUsername = authentication.getName();
        EncryptedMessageDto message = messageService.sendMessage(senderUsername, request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Message relayed successfully", message));
    }

    /**
     * Retrieves all pending messages queued for the authenticated user and marks them as DELIVERED.
     */
    @GetMapping("/pending")
    public ResponseEntity<ApiResponse<List<EncryptedMessageDto>>> getPendingMessages(Authentication authentication) {
        String username = authentication.getName();
        List<EncryptedMessageDto> messages = messageService.getPendingMessages(username);
        return ResponseEntity.ok(ApiResponse.ok("Pending messages retrieved", messages));
    }

    /**
     * Retrieves encrypted message history between the authenticated user and a peer.
     */
    @GetMapping("/conversation/{peerUsername}")
    public ResponseEntity<ApiResponse<List<EncryptedMessageDto>>> getConversationHistory(
            @PathVariable("peerUsername") String peerUsername,
            Authentication authentication) {
        String username = authentication.getName();
        List<EncryptedMessageDto> history = messageService.getConversationHistory(username, peerUsername);
        return ResponseEntity.ok(ApiResponse.ok("Conversation history retrieved", history));
    }

    /**
     * Acknowledges message delivery or updates read receipt status.
     */
    @PutMapping("/{messageId}/status")
    public ResponseEntity<ApiResponse<EncryptedMessageDto>> updateMessageStatus(
            @PathVariable("messageId") String messageId,
            @jakarta.validation.Valid @RequestBody DeliveryReceiptRequest request,
            Authentication authentication) {
        String recipientUsername = authentication.getName();
        MessageStatus status = MessageStatus.valueOf(request.status().toUpperCase());
        EncryptedMessageDto updated = messageService.updateMessageStatus(recipientUsername, messageId, status);
        return ResponseEntity.ok(ApiResponse.ok("Message status updated", updated));
    }
}
