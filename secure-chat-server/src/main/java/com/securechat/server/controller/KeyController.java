package com.securechat.server.controller;

import com.securechat.common.dto.ApiResponse;
import com.securechat.common.dto.KeyExchangeBundleDto;
import com.securechat.common.dto.PrekeyCountResponse;
import com.securechat.common.dto.PublishKeyBundleRequest;
import com.securechat.common.dto.UploadPrekeysRequest;
import com.securechat.common.dto.UserKeyBundleDto;
import com.securechat.server.entity.UserKeyBundleEntity;
import com.securechat.server.service.KeyManagementService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for Post-Quantum Cryptographic key publication, rotation,
 * prekey replenishment, and PQ-X3DH session key bundle discovery.
 * All endpoints require valid JWT Bearer authentication.
 */
@RestController
@RequestMapping("/api/v1/keys")
public class KeyController {

    private final KeyManagementService keyManagementService;

    public KeyController(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    /**
     * Publishes or rotates the authenticated user's Post-Quantum Cryptographic Key Bundle.
     * The server cryptographically validates the ML-DSA signature over the ML-KEM prekey.
     */
    @PostMapping("/bundle")
    public ResponseEntity<ApiResponse<UserKeyBundleDto>> publishKeyBundle(
            @RequestBody PublishKeyBundleRequest request,
            Authentication authentication) {
        String username = authentication.getName();
        UserKeyBundleEntity bundle = keyManagementService.publishKeyBundle(username, request);

        UserKeyBundleDto dto = new UserKeyBundleDto(
                bundle.getUser().getId(),
                bundle.getUser().getUsername(),
                bundle.getPrekey(),
                bundle.getPrekeyAlgorithm(),
                bundle.getIdentityKey(),
                bundle.getIdentityAlgorithm(),
                bundle.getKeyVersion(),
                bundle.getCreatedAt()
        );

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Post-Quantum key bundle published successfully", dto));
    }

    /**
     * Replenishes one-time prekeys (ML-KEM-768) for the authenticated user.
     */
    @PostMapping("/prekeys")
    public ResponseEntity<ApiResponse<Integer>> uploadPrekeys(
            @RequestBody UploadPrekeysRequest request,
            Authentication authentication) {
        String username = authentication.getName();
        int count = keyManagementService.uploadOneTimePrekeys(username, request);
        return ResponseEntity.ok(ApiResponse.ok("Successfully uploaded " + count + " one-time prekeys", count));
    }

    /**
     * Returns the remaining count and stock status of unused one-time prekeys for the authenticated user.
     */
    @GetMapping("/prekeys/count")
    public ResponseEntity<ApiResponse<PrekeyCountResponse>> getPrekeyCount(Authentication authentication) {
        String username = authentication.getName();
        PrekeyCountResponse response = keyManagementService.getPrekeyCount(username);
        return ResponseEntity.ok(ApiResponse.ok("Prekey count retrieved", response));
    }

    /**
     * Fetches the recipient's active public key bundle and atomically claims one unused OPK
     * to initiate an asynchronous PQ-X3DH messaging session.
     */
    @GetMapping("/user/{username}")
    public ResponseEntity<ApiResponse<KeyExchangeBundleDto>> getKeyExchangeBundleByUsername(
            @PathVariable("username") String username) {
        KeyExchangeBundleDto bundle = keyManagementService.getKeyExchangeBundle(username);
        return ResponseEntity.ok(ApiResponse.ok("Key exchange bundle retrieved successfully", bundle));
    }

    /**
     * Fetches the recipient's active public key bundle by user ID and claims one OPK.
     */
    @GetMapping("/{userId}")
    public ResponseEntity<ApiResponse<KeyExchangeBundleDto>> getKeyExchangeBundleById(
            @PathVariable("userId") Long userId) {
        KeyExchangeBundleDto bundle = keyManagementService.getKeyExchangeBundleById(userId);
        return ResponseEntity.ok(ApiResponse.ok("Key exchange bundle retrieved successfully", bundle));
    }
}
