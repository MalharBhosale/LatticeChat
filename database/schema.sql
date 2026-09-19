-- ============================================================================
-- LatticeChat (SecureChat) — Post-Quantum Secure Messaging Application
-- Database Schema Definition (MySQL 8.0+)
--
-- Security Design:
-- 1. Zero-Knowledge: The server NEVER stores plaintext messages or private keys.
-- 2. Post-Quantum Sized: Public key and signature columns are sized for NIST
--    FIPS 203 (ML-KEM-768/1024) and FIPS 204 (ML-DSA-65/87) Base64 strings.
-- 3. Auditability: Full audit trail of security-sensitive operations.
-- ============================================================================

CREATE DATABASE IF NOT EXISTS `securechat_db`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE `securechat_db`;

-- ----------------------------------------------------------------------------
-- Table: users
-- Stores user identity and authentication credentials (salted & hashed).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL,
    `email` VARCHAR(100) NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `display_name` VARCHAR(100) NULL,
    `status` VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT `uk_users_username` UNIQUE (`username`),
    CONSTRAINT `uk_users_email` UNIQUE (`email`),
    INDEX `idx_users_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table: user_key_bundles
-- Stores user's published Post-Quantum Identity (ML-DSA) and Prekey (ML-KEM)
-- bundles. Used for authenticated key exchange establishment.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `user_key_bundles` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `user_id` BIGINT NOT NULL,
    `identity_key` TEXT NOT NULL,
    `identity_algorithm` VARCHAR(50) NOT NULL DEFAULT 'ML-DSA-65',
    `prekey` TEXT NOT NULL,
    `prekey_algorithm` VARCHAR(50) NOT NULL DEFAULT 'ML-KEM-768',
    `prekey_signature` TEXT NOT NULL,
    `key_version` INT NOT NULL DEFAULT 1,
    `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `expires_at` TIMESTAMP NULL,
    CONSTRAINT `fk_keybundles_user` FOREIGN KEY (`user_id`)
        REFERENCES `users` (`id`) ON DELETE CASCADE,
    INDEX `idx_keybundles_user_active` (`user_id`, `is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table: one_time_prekeys
-- Pre-published one-time ML-KEM encapsulation keys for asynchronous offline
-- messaging (PQ-X3DH protocol).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `one_time_prekeys` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `user_id` BIGINT NOT NULL,
    `key_id` INT NOT NULL,
    `public_key` TEXT NOT NULL,
    `algorithm` VARCHAR(50) NOT NULL DEFAULT 'ML-KEM-768',
    `is_consumed` BOOLEAN NOT NULL DEFAULT FALSE,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `consumed_at` TIMESTAMP NULL,
    CONSTRAINT `fk_otk_user` FOREIGN KEY (`user_id`)
        REFERENCES `users` (`id`) ON DELETE CASCADE,
    INDEX `idx_otk_lookup` (`user_id`, `is_consumed`, `id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table: messages
-- Stores zero-knowledge encrypted messages awaiting delivery or historical sync.
-- Plaintext is NEVER stored. Ciphertext is AES-256-GCM.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `messages` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `message_id` VARCHAR(64) NOT NULL,
    `sender_id` BIGINT NOT NULL,
    `recipient_id` BIGINT NOT NULL,
    `ciphertext` LONGTEXT NOT NULL,
    `nonce` VARCHAR(64) NOT NULL,
    `auth_tag` VARCHAR(64) NULL,
    `ephemeral_kem_ciphertext` TEXT NULL,
    `signature` TEXT NOT NULL,
    `sequence_number` BIGINT NOT NULL DEFAULT 1,
    `status` VARCHAR(20) NOT NULL DEFAULT 'SENT',
    `sent_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `delivered_at` TIMESTAMP NULL,
    `read_at` TIMESTAMP NULL,
    CONSTRAINT `uk_messages_message_id` UNIQUE (`message_id`),
    CONSTRAINT `fk_messages_sender` FOREIGN KEY (`sender_id`)
        REFERENCES `users` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_messages_recipient` FOREIGN KEY (`recipient_id`)
        REFERENCES `users` (`id`) ON DELETE CASCADE,
    INDEX `idx_messages_recipient_status` (`recipient_id`, `status`),
    INDEX `idx_messages_conversation` (`sender_id`, `recipient_id`, `sent_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table: audit_logs
-- Immutable security events tracking authentication, key uploads, and anomalies.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `user_id` BIGINT NULL,
    `event_type` VARCHAR(50) NOT NULL,
    `ip_address` VARCHAR(45) NULL,
    `details` TEXT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`)
        REFERENCES `users` (`id`) ON DELETE SET NULL,
    INDEX `idx_audit_event_time` (`event_type`, `created_at`),
    INDEX `idx_audit_user_time` (`user_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
