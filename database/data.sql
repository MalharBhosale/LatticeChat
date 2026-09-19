-- ============================================================================
-- LatticeChat — Sample Seed Data for Development & Testing
-- Passwords: All default users have the password 'Password123!'
-- BCrypt Hash: $2a$12$6mCtMXKVYCiXMsqePMfreOo.tp.RfbFleKEkhNfUnbR4PCqVWqwKq
-- ============================================================================

USE `securechat_db`;

-- Insert Seed Users
INSERT INTO `users` (`id`, `username`, `email`, `password_hash`, `display_name`, `status`)
VALUES
    (1, 'alice', 'alice@securechat.internal', '$2a$12$6mCtMXKVYCiXMsqePMfreOo.tp.RfbFleKEkhNfUnbR4PCqVWqwKq', 'Alice Quantum', 'ACTIVE'),
    (2, 'bob', 'bob@securechat.internal', '$2a$12$6mCtMXKVYCiXMsqePMfreOo.tp.RfbFleKEkhNfUnbR4PCqVWqwKq', 'Bob Lattice', 'ACTIVE'),
    (3, 'charlie', 'charlie@securechat.internal', '$2a$12$6mCtMXKVYCiXMsqePMfreOo.tp.RfbFleKEkhNfUnbR4PCqVWqwKq', 'Charlie Observer', 'ACTIVE')
ON DUPLICATE KEY UPDATE `display_name` = VALUES(`display_name`), `password_hash` = VALUES(`password_hash`);


-- Insert Initial Audit Logs
INSERT INTO `audit_logs` (`user_id`, `event_type`, `ip_address`, `details`)
VALUES
    (1, 'USER_REGISTER', '127.0.0.1', 'Alice account registered successfully.'),
    (2, 'USER_REGISTER', '127.0.0.1', 'Bob account registered successfully.'),
    (1, 'KEY_UPLOAD', '127.0.0.1', 'Alice uploaded ML-DSA-65 identity and ML-KEM-768 prekey bundle.'),
    (2, 'KEY_UPLOAD', '127.0.0.1', 'Bob uploaded ML-DSA-65 identity and ML-KEM-768 prekey bundle.');
