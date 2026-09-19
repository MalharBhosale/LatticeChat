package com.securechat.common.exception;

public class AuthorizationException extends SecureChatException {
    public AuthorizationException(String message) {
        super(message);
    }
    public AuthorizationException(String message, Throwable cause) {
        super(message, cause);
    }
}
