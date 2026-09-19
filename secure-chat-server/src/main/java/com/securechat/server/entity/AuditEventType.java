package com.securechat.server.entity;

/**
 * Security audit event classifications for security tracking and forensics.
 */
public enum AuditEventType {
    USER_REGISTER,
    USER_LOGIN,
    LOGIN_FAILED,
    KEY_UPLOAD,
    KEY_ROTATION,
    MESSAGE_SENT,
    MESSAGE_DELIVERED,
    REPLAY_ATTACK_DETECTED,
    SIGNATURE_VERIFICATION_FAILED
}
