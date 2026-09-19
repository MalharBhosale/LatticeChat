package com.securechat.common.exception;

public class MessageDecryptionException extends CryptoException {
    public MessageDecryptionException(String message) {
        super(message);
    }
    public MessageDecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
