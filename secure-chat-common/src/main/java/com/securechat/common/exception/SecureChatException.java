package com.securechat.common.exception;

/**
 * Base unchecked exception for all SecureChat domain and cryptographic errors.
 */
public class SecureChatException extends RuntimeException {
    public SecureChatException(String message) {
        super(message);
    }

    public SecureChatException(String message, Throwable cause) {
        super(message, cause);
    }
}
