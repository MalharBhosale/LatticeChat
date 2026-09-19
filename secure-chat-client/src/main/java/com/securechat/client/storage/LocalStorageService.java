package com.securechat.client.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.sql.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Local SQLite storage service managing encrypted session keys and local message history.
 */
public class LocalStorageService implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(LocalStorageService.class);

    private final Connection connection;

    public LocalStorageService(String dbPath) throws SQLException {
        if (!dbPath.startsWith("jdbc:sqlite:")) {
            File dbFile = new File(dbPath);
            if (dbFile.getParentFile() != null) {
                dbFile.getParentFile().mkdirs();
            }
            dbPath = "jdbc:sqlite:" + dbPath;
        }

        this.connection = DriverManager.getConnection(dbPath);
        initSchema();
    }

    public static LocalStorageService forUser(String username) throws SQLException {
        String userHome = System.getProperty("user.home");
        File dir = new File(userHome, ".latticechat");
        dir.mkdirs();
        File dbFile = new File(dir, username + ".db");
        return new LocalStorageService(dbFile.getAbsolutePath());
    }

    public static LocalStorageService inMemory() throws SQLException {
        return new LocalStorageService("jdbc:sqlite::memory:");
    }

    private void initSchema() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS local_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT UNIQUE NOT NULL,
                    peer_username TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    plaintext TEXT NOT NULL,
                    status TEXT NOT NULL,
                    sequence_number INTEGER,
                    timestamp TEXT NOT NULL
                );
            """);

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS peer_sessions (
                    peer_username TEXT PRIMARY KEY,
                    session_key_b64 TEXT NOT NULL,
                    peer_identity_key_b64 TEXT,
                    established_at TEXT NOT NULL
                );
            """);

            stmt.execute("CREATE INDEX IF NOT EXISTS idx_msg_peer ON local_messages(peer_username);");
        }
    }

    public synchronized void saveMessage(LocalMessage message) throws SQLException {
        String sql = """
            INSERT OR REPLACE INTO local_messages 
            (message_id, peer_username, direction, plaintext, status, sequence_number, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        """;

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, message.messageId());
            ps.setString(2, message.peerUsername());
            ps.setString(3, message.direction());
            ps.setString(4, message.plaintext());
            ps.setString(5, message.status());
            if (message.sequenceNumber() != null) {
                ps.setLong(6, message.sequenceNumber());
            } else {
                ps.setNull(6, Types.INTEGER);
            }
            ps.setString(7, message.timestamp().toString());
            ps.executeUpdate();
        }
    }

    public synchronized void updateMessageStatus(String messageId, String status) throws SQLException {
        String sql = "UPDATE local_messages SET status = ? WHERE message_id = ?;";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, status);
            ps.setString(2, messageId);
            ps.executeUpdate();
        }
    }

    public synchronized List<LocalMessage> getMessagesForPeer(String peerUsername) throws SQLException {
        String sql = "SELECT * FROM local_messages WHERE peer_username = ? ORDER BY timestamp ASC;";
        List<LocalMessage> list = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, peerUsername);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(mapResultSetToMessage(rs));
                }
            }
        }
        return list;
    }

    public synchronized List<String> getRecentPeers() throws SQLException {
        String sql = "SELECT DISTINCT peer_username FROM local_messages ORDER BY timestamp DESC;";
        List<String> peers = new ArrayList<>();
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                peers.add(rs.getString("peer_username"));
            }
        }
        return peers;
    }

    public synchronized void saveSession(String peerUsername, String sessionKeyB64, String peerIdentityKeyB64) throws SQLException {
        String sql = """
            INSERT OR REPLACE INTO peer_sessions 
            (peer_username, session_key_b64, peer_identity_key_b64, established_at)
            VALUES (?, ?, ?, ?);
        """;

        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, peerUsername);
            ps.setString(2, sessionKeyB64);
            ps.setString(3, peerIdentityKeyB64);
            ps.setString(4, Instant.now().toString());
            ps.executeUpdate();
        }
    }

    public synchronized Optional<String> getSessionKey(String peerUsername) throws SQLException {
        String sql = "SELECT session_key_b64 FROM peer_sessions WHERE peer_username = ?;";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, peerUsername);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(rs.getString("session_key_b64"));
                }
            }
        }
        return Optional.empty();
    }

    public synchronized Optional<String> getPeerIdentityKey(String peerUsername) throws SQLException {
        String sql = "SELECT peer_identity_key_b64 FROM peer_sessions WHERE peer_username = ?;";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, peerUsername);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.ofNullable(rs.getString("peer_identity_key_b64"));
                }
            }
        }
        return Optional.empty();
    }

    public synchronized boolean hasSession(String peerUsername) throws SQLException {
        return getSessionKey(peerUsername).isPresent();
    }

    private LocalMessage mapResultSetToMessage(ResultSet rs) throws SQLException {
        return new LocalMessage(
                rs.getLong("id"),
                rs.getString("message_id"),
                rs.getString("peer_username"),
                rs.getString("direction"),
                rs.getString("plaintext"),
                rs.getString("status"),
                rs.getObject("sequence_number") != null ? rs.getLong("sequence_number") : null,
                Instant.parse(rs.getString("timestamp"))
        );
    }

    @Override
    public synchronized void close() throws Exception {
        if (connection != null && !connection.isClosed()) {
            connection.close();
        }
    }
}
