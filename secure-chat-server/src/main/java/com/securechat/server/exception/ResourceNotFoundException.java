package com.securechat.server.exception;

import com.securechat.common.exception.SecureChatException;

/**
 * Exception thrown when a requested resource (user, key bundle, message) cannot be found.
 */
public class ResourceNotFoundException extends SecureChatException {

    public ResourceNotFoundException(String message) {
        super(message);
    }
}
