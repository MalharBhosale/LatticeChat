package com.securechat.common.exception;

public class CryptoException extends SecureChatException {
    public CryptoException(String message) {
        super(message);
    }
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
