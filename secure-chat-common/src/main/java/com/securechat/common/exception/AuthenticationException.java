package com.securechat.common.exception;

public class AuthenticationException extends SecureChatException {
    public AuthenticationException(String message) {
        super(message);
    }
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
