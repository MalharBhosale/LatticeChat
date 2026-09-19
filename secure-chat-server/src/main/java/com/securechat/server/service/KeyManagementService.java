package com.securechat.server.service;

import com.securechat.common.crypto.SignatureService;
import com.securechat.common.dto.KeyExchangeBundleDto;
import com.securechat.common.dto.OneTimePrekeyUploadDto;
import com.securechat.common.dto.PrekeyCountResponse;
import com.securechat.common.dto.PublishKeyBundleRequest;
import com.securechat.common.dto.UploadPrekeysRequest;
import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.AuditLogEntity;
import com.securechat.server.entity.OneTimePrekeyEntity;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.entity.UserKeyBundleEntity;
import com.securechat.server.exception.ResourceNotFoundException;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.OneTimePrekeyRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
import com.securechat.server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Service managing Post-Quantum Cryptographic key bundles (NIST FIPS 203 & 204),
 * signed prekey verification, one-time prekey replenishment, and PQ-X3DH session key discovery.
 */
@Service
public class KeyManagementService {

    private static final Logger log = LoggerFactory.getLogger(KeyManagementService.class);

    private final UserRepository userRepository;
    private final UserKeyBundleRepository userKeyBundleRepository;
    private final OneTimePrekeyRepository oneTimePrekeyRepository;
    private final AuditLogRepository auditLogRepository;
    private final SignatureService signatureService;

    public KeyManagementService(UserRepository userRepository,
                                UserKeyBundleRepository userKeyBundleRepository,
                                OneTimePrekeyRepository oneTimePrekeyRepository,
                                AuditLogRepository auditLogRepository,
                                SignatureService signatureService) {
        this.userRepository = userRepository;
        this.userKeyBundleRepository = userKeyBundleRepository;
        this.oneTimePrekeyRepository = oneTimePrekeyRepository;
        this.auditLogRepository = auditLogRepository;
        this.signatureService = signatureService;
    }

    /**
     * Publishes or rotates a user's Post-Quantum Cryptographic Key Bundle.
     * Validates that the prekey is authentically signed by the identity key before persisting.
     */
    @Transactional(noRollbackFor = IllegalArgumentException.class)
    public UserKeyBundleEntity publishKeyBundle(String username, PublishKeyBundleRequest request) {
        if (request == null || request.identityKey() == null || request.prekey() == null || request.prekeySignature() == null) {
            throw new IllegalArgumentException("Identity key, prekey, and prekey signature are required");
        }

        // 1. Verify ML-DSA signature over the ML-KEM prekey
        try {
            byte[] identityKeyBytes = Base64.getDecoder().decode(request.identityKey());
            byte[] prekeyBytes = Base64.getDecoder().decode(request.prekey());
            byte[] signatureBytes = Base64.getDecoder().decode(request.prekeySignature());

            boolean isValid = signatureService.verify(prekeyBytes, signatureBytes, identityKeyBytes);
            if (!isValid) {
                log.warn("Cryptographic verification failed for prekey signature from user '{}'", username);
                recordAuditLog(username, AuditEventType.SIGNATURE_VERIFICATION_FAILED,
                        "Prekey signature verification failed for user: " + username);
                throw new IllegalArgumentException("Invalid prekey signature. The prekey must be signed by the identity key.");
            }
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Failed to parse or verify prekey signature for user '{}': {}", username, ex.getMessage());
            recordAuditLog(username, AuditEventType.SIGNATURE_VERIFICATION_FAILED,
                    "Malformed signature or key encoding: " + ex.getMessage());
            throw new IllegalArgumentException("Invalid key encoding or signature format: " + ex.getMessage());
        }

        // 2. Fetch user
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User '" + username + "' not found"));

        // 3. Determine next key version and deactivate previous active bundles
        int nextVersion = userKeyBundleRepository.findByUserIdAndIsActiveTrue(user.getId())
                .map(b -> b.getKeyVersion() + 1)
                .orElse(1);

        userKeyBundleRepository.deactivateAllByUserId(user.getId());

        // 4. Persist new active key bundle
        UserKeyBundleEntity bundle = new UserKeyBundleEntity(
                user,
                request.identityKey(),
                request.identityAlgorithm(),
                request.prekey(),
                request.prekeyAlgorithm(),
                request.prekeySignature(),
                nextVersion
        );
        UserKeyBundleEntity savedBundle = userKeyBundleRepository.save(bundle);

        // 5. Store one-time prekeys if included
        if (request.oneTimePrekeys() != null && !request.oneTimePrekeys().isEmpty()) {
            List<OneTimePrekeyEntity> prekeyEntities = request.oneTimePrekeys().stream()
                    .map(dto -> new OneTimePrekeyEntity(user, dto.keyId(), dto.publicKey(), dto.algorithm()))
                    .toList();
            oneTimePrekeyRepository.saveAll(prekeyEntities);
            log.info("Stored {} initial one-time prekeys for user '{}'", prekeyEntities.size(), username);
        }

        // 6. Security audit trail
        AuditEventType eventType = nextVersion > 1 ? AuditEventType.KEY_ROTATION : AuditEventType.KEY_UPLOAD;
        recordAuditLog(user, eventType, "Published PQC key bundle version " + nextVersion);

        log.info("Successfully published PQC key bundle v{} for user '{}'", nextVersion, username);
        return savedBundle;
    }

    /**
     * Rotates a user's signed prekey (ML-KEM-768), verifies the signature using their permanent
     * ML-DSA-65 identity key, increments the key version, and records an audit log.
     */
    @Transactional(noRollbackFor = IllegalArgumentException.class)
    public UserKeyBundleEntity rotateSignedPrekey(String username, com.securechat.common.dto.RotateKeyBundleRequest request) {
        if (request == null || request.newPrekey() == null || request.newPrekeySignature() == null) {
            throw new IllegalArgumentException("New prekey and prekey signature are required for rotation");
        }

        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User '" + username + "' not found"));

        UserKeyBundleEntity currentBundle = userKeyBundleRepository.findByUserIdAndIsActiveTrue(user.getId())
                .orElseThrow(() -> new IllegalStateException("Cannot rotate keys: no active key bundle found for user: " + username));

        // 1. Verify ML-DSA signature over the new prekey using permanent identity key
        try {
            byte[] identityKeyBytes = Base64.getDecoder().decode(currentBundle.getIdentityKey());
            byte[] prekeyBytes = Base64.getDecoder().decode(request.newPrekey());
            byte[] signatureBytes = Base64.getDecoder().decode(request.newPrekeySignature());

            boolean isValid = signatureService.verify(prekeyBytes, signatureBytes, identityKeyBytes);
            if (!isValid) {
                log.warn("Cryptographic verification failed for rotated prekey signature from user '{}'", username);
                recordAuditLog(username, AuditEventType.SIGNATURE_VERIFICATION_FAILED,
                        "Rotated prekey signature verification failed for user: " + username);
                throw new IllegalArgumentException("Invalid prekey signature. The prekey must be signed by the identity key.");
            }
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Failed to parse or verify rotated prekey signature for user '{}': {}", username, ex.getMessage());
            recordAuditLog(username, AuditEventType.SIGNATURE_VERIFICATION_FAILED,
                    "Malformed signature or key encoding during rotation: " + ex.getMessage());
            throw new IllegalArgumentException("Invalid key encoding or signature format: " + ex.getMessage());
        }

        // 2. Deactivate existing active bundle and increment key version
        int nextVersion = currentBundle.getKeyVersion() + 1;
        userKeyBundleRepository.deactivateAllByUserId(user.getId());

        // 3. Persist new active bundle
        String prekeyAlgo = request.newPrekeyAlgorithm() != null ? request.newPrekeyAlgorithm() : "ML-KEM-768";
        UserKeyBundleEntity newBundle = new UserKeyBundleEntity(
                user,
                currentBundle.getIdentityKey(),
                currentBundle.getIdentityAlgorithm(),
                request.newPrekey(),
                prekeyAlgo,
                request.newPrekeySignature(),
                nextVersion
        );
        UserKeyBundleEntity savedBundle = userKeyBundleRepository.save(newBundle);

        // 4. Save any additional one-time prekeys
        if (request.oneTimePrekeys() != null && !request.oneTimePrekeys().isEmpty()) {
            List<OneTimePrekeyEntity> prekeyEntities = request.oneTimePrekeys().stream()
                    .map(dto -> new OneTimePrekeyEntity(user, dto.keyId(), dto.publicKey(), dto.algorithm()))
                    .toList();
            oneTimePrekeyRepository.saveAll(prekeyEntities);
            log.info("Stored {} replenished one-time prekeys during key rotation for user '{}'", prekeyEntities.size(), username);
        }

        // 5. Security audit trail
        recordAuditLog(user, AuditEventType.KEY_ROTATION,
                "Rotated PQC signed prekey to version " + nextVersion);

        log.info("Successfully rotated PQC key bundle to v{} for user '{}'", nextVersion, username);
        return savedBundle;
    }

    /**
     * Explicitly revokes and deactivates the user's active Post-Quantum Key Bundle,
     * invalidates all unconsumed one-time prekeys, and writes a KEY_REVOCATION audit event.
     */
    @Transactional
    public void revokeActiveKeyBundle(String username, com.securechat.common.dto.RevokeKeyBundleRequest request) {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User '" + username + "' not found"));

        UserKeyBundleEntity currentBundle = userKeyBundleRepository.findByUserIdAndIsActiveTrue(user.getId())
                .orElseThrow(() -> new IllegalStateException("Cannot revoke keys: no active key bundle found for user: " + username));

        int revokedVersion = currentBundle.getKeyVersion();

        // 1. Deactivate active bundle
        userKeyBundleRepository.deactivateAllByUserId(user.getId());

        // 2. Consume and invalidate remaining one-time prekeys
        List<OneTimePrekeyEntity> unconsumedOpks = oneTimePrekeyRepository.findByUserIdAndIsConsumedFalse(user.getId());
        for (OneTimePrekeyEntity opk : unconsumedOpks) {
            opk.markConsumed();
        }
        oneTimePrekeyRepository.saveAll(unconsumedOpks);

        // 3. Security audit trail
        String reason = (request != null && request.reason() != null) ? request.reason() : "USER_REQUESTED";
        String notes = (request != null && request.notes() != null) ? " (" + request.notes() + ")" : "";
        recordAuditLog(user, AuditEventType.KEY_REVOCATION,
                "Revoked active PQC key bundle version " + revokedVersion + ". Reason: " + reason + notes);

        log.warn("Revoked active PQC key bundle v{} and invalidated {} OPKs for user '{}'. Reason: {}",
                revokedVersion, unconsumedOpks.size(), username, reason);
    }

    /**
     * Retrieves the complete cryptographic audit trail for the specified user.
     */
    @Transactional(readOnly = true)
    public List<com.securechat.common.dto.AuditLogDto> getUserAuditTrail(String username) {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User '" + username + "' not found"));

        return auditLogRepository.findByUserIdOrderByCreatedAtDesc(user.getId()).stream()
                .map(log -> new com.securechat.common.dto.AuditLogDto(
                        log.getId(),
                        user.getUsername(),
                        log.getEventType().name(),
                        log.getIpAddress(),
                        log.getDetails(),
                        log.getCreatedAt()
                ))
                .toList();
    }


    /**
     * Replenishes a user's pool of unconsumed one-time prekeys (ML-KEM-768).
     */
    @Transactional
    public int uploadOneTimePrekeys(String username, UploadPrekeysRequest request) {
        if (request == null || request.prekeys() == null || request.prekeys().isEmpty()) {
            throw new IllegalArgumentException("Prekey list must not be empty");
        }

        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User '" + username + "' not found"));

        List<OneTimePrekeyEntity> entities = request.prekeys().stream()
                .map(dto -> new OneTimePrekeyEntity(user, dto.keyId(), dto.publicKey(), dto.algorithm()))
                .toList();

        oneTimePrekeyRepository.saveAll(entities);

        recordAuditLog(user, AuditEventType.KEY_UPLOAD, "Uploaded " + entities.size() + " one-time prekeys");
        log.info("Replenished {} one-time prekeys for user '{}'", entities.size(), username);
        return entities.size();
    }

    /**
     * Retrieves the recipient's active public key bundle and atomically claims
     * one unused one-time prekey in FIFO order for initiating a PQ-X3DH session.
     */
    @Transactional
    public KeyExchangeBundleDto getKeyExchangeBundle(String recipientUsername) {
        UserKeyBundleEntity bundle = userKeyBundleRepository.findByUserUsernameAndIsActiveTrue(recipientUsername)
                .orElseThrow(() -> new ResourceNotFoundException("Active key bundle not found for user: " + recipientUsername));

        return claimAndBuildBundle(bundle, () ->
                oneTimePrekeyRepository.findFirstByUserUsernameAndIsConsumedFalseOrderByIdAsc(recipientUsername));
    }

    /**
     * Retrieves the recipient's active public key bundle by user ID and claims one OPK.
     */
    @Transactional
    public KeyExchangeBundleDto getKeyExchangeBundleById(Long recipientUserId) {
        UserKeyBundleEntity bundle = userKeyBundleRepository.findByUserIdAndIsActiveTrue(recipientUserId)
                .orElseThrow(() -> new ResourceNotFoundException("Active key bundle not found for user ID: " + recipientUserId));

        return claimAndBuildBundle(bundle, () ->
                oneTimePrekeyRepository.findFirstByUserIdAndIsConsumedFalseOrderByIdAsc(recipientUserId));
    }

    /**
     * Checks the remaining count of unused one-time prekeys for a user.
     */
    @Transactional(readOnly = true)
    public PrekeyCountResponse getPrekeyCount(String username) {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User '" + username + "' not found"));

        long remaining = oneTimePrekeyRepository.countByUserIdAndIsConsumedFalse(user.getId());
        boolean lowStock = remaining < 5;

        return new PrekeyCountResponse(remaining, lowStock);
    }

    private KeyExchangeBundleDto claimAndBuildBundle(
            UserKeyBundleEntity bundle,
            java.util.function.Supplier<Optional<OneTimePrekeyEntity>> opkSupplier) {

        Optional<OneTimePrekeyEntity> opkOpt = opkSupplier.get();
        Integer opkId = null;
        String opkKey = null;
        String opkAlgorithm = null;

        if (opkOpt.isPresent()) {
            OneTimePrekeyEntity opk = opkOpt.get();
            opk.markConsumed();
            oneTimePrekeyRepository.save(opk);
            opkId = opk.getKeyId();
            opkKey = opk.getPublicKey();
            opkAlgorithm = opk.getAlgorithm();
            log.debug("Consumed one-time prekey id={} for user '{}'", opk.getId(), bundle.getUser().getUsername());
        } else {
            log.warn("One-time prekeys exhausted for user '{}', session will proceed with signed prekey only",
                    bundle.getUser().getUsername());
        }

        return new KeyExchangeBundleDto(
                bundle.getUser().getId(),
                bundle.getUser().getUsername(),
                bundle.getIdentityKey(),
                bundle.getIdentityAlgorithm(),
                bundle.getPrekey(),
                bundle.getPrekeyAlgorithm(),
                bundle.getPrekeySignature(),
                opkId,
                opkKey,
                opkAlgorithm,
                bundle.getKeyVersion()
        );
    }

    private void recordAuditLog(String username, AuditEventType eventType, String details) {
        UserEntity user = userRepository.findByUsername(username).orElse(null);
        recordAuditLog(user, eventType, details);
    }

    private void recordAuditLog(UserEntity user, AuditEventType eventType, String details) {
        try {
            auditLogRepository.save(new AuditLogEntity(user, eventType, "127.0.0.1", details));
        } catch (Exception e) {
            log.error("Failed to write audit log for event {}: {}", eventType, e.getMessage());
        }
    }
}
