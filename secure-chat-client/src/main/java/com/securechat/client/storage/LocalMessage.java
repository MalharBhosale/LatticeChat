package com.securechat.client.storage;

import java.time.Instant;

/**
 * Local plaintext message representation stored in client-side SQLite database.
 */
public record LocalMessage(
        Long id,
        String messageId,
        String peerUsername,
        String direction, // "OUTGOING" or "INCOMING"
        String plaintext,
        String status,    // "SENT", "DELIVERED", "READ"
        Long sequenceNumber,
        Instant timestamp
) {}
