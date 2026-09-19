# LatticeChat — System Architecture & Component Engineering

**Architecture Classification**: Multi-Module Distributed Cryptographic System  
**Frameworks**: Java 21 LTS, Spring Boot 3.3, JavaFX 21, Bouncy Castle PQC 1.78.1, SQLite, MySQL / PostgreSQL  
**Author**: Malhar Bhosale  

---

## 1. High-Level Architectural Vision

LatticeChat is built upon the premise that **the network and the relay server must be treated as untrusted, potentially hostile environments**. Confidentiality must not depend upon transport encryption (TLS) alone, nor upon cloud database security.

```mermaid
graph TB
    subgraph ClientA ["LatticeChat Client A (Desktop)"]
        UI_A["JavaFX 21 UI & Controllers"]
        Engine_A["Client Keystore & SessionManager"]
        Crypto_A["PQC Engine (ML-KEM, ML-DSA, AES-GCM)"]
        DB_A["Local SQLite (Encrypted Conversations)"]
        UI_A --> Engine_A
        Engine_A --> Crypto_A
        Engine_A --> DB_A
    end

    subgraph Network ["Untrusted Transport & Relay"]
        REST["HTTPS REST API (JSON / Multipart)"]
        WS["WSS WebSocket (STOMP Protocol)"]
    end

    subgraph Server ["LatticeChat Relay Server (Spring Boot 3)"]
        Filter["Spring Security Filter / Rate Limiter"]
        Controller["KeyController / MessageController / AttachmentController"]
        Services["KeyService / MessageService / AttachmentService"]
        AuditService["AuditLogService & NotificationService"]
        Repo["Spring Data JPA Repositories"]
        RDBMS[("Relational DB (PostgreSQL / MySQL / H2)")]
        DiskVault["File Storage Vault (UUID Storage)"]

        Filter --> Controller
        Controller --> Services
        Services --> AuditService
        Services --> Repo
        Repo --> RDBMS
        Services --> DiskVault
    end

    subgraph ClientB ["LatticeChat Client B (Desktop)"]
        UI_B["JavaFX 21 UI & Controllers"]
        Engine_B["Client Keystore & SessionManager"]
        Crypto_B["PQC Engine (ML-KEM, ML-DSA, AES-GCM)"]
        DB_B["Local SQLite (Encrypted Conversations)"]
        UI_B --> Engine_B
        Engine_B --> Crypto_B
        Engine_B --> DB_B
    end

    ClientA <==>|Encrypted Envelopes| REST
    ClientA <==>|Real-time STOMP Events| WS
    REST <==> Filter
    WS <==> Filter
    REST <==> ClientB
    WS <==> ClientB

    classDef clientStyle fill:#e1f5fe,stroke:#039be5,stroke-width:2px;
    classDef serverStyle fill:#f3e5f5,stroke:#8e24aa,stroke-width:2px;
    classDef netStyle fill:#fffde7,stroke:#fbc02d,stroke-width:2px;

    class UI_A,Engine_A,Crypto_A,DB_A,UI_B,Engine_B,Crypto_B,DB_B clientStyle;
    class Filter,Controller,Services,AuditService,Repo,RDBMS,DiskVault serverStyle;
    class REST,WS netStyle;
```

---

## 2. Multi-Module Reactor Architecture

The project is partitioned into three decoupled modules:

```
LatticeChat (Parent POM)
│
├── secure-chat-common/        <-- Pure Cryptographic Engine & Shared Protocols
│   ├── crypto/                <-- ML-KEM, ML-DSA, AES-GCM, HKDF
│   ├── crypto/stream/         <-- 64 KB Chunking Streaming Engine
│   ├── crypto/benchmark/      <-- High-Resolution Monotonic Benchmarking Suite
│   ├── dto/                   <-- Type-Safe Network Payloads (Records)
│   └── util/                  <-- SafePathUtils & Base64 Encoders
│
├── secure-chat-server/        <-- Zero-Knowledge Blind Relay Hub
│   ├── controller/            <-- REST API Endpoints (Auth, Keys, Messages, Files)
│   ├── service/               <-- Business Logic & Atomic Synchronization
│   ├── repository/            <-- Spring Data JPA Data Access
│   ├── entity/                <-- Zero-Knowledge Database Entities
│   ├── security/              <-- JWT Authentication Filters & Rate Limiting
│   └── websocket/             <-- STOMP Message Broker & Presence
│
└── secure-chat-client/        <-- Sovereign Desktop Application
    ├── controller/            <-- JavaFX UI Controllers (Chat, Lab, Dashboard)
    ├── crypto/                <-- Client In-Memory Keystore & Key Rotation
    ├── protocol/              <-- Double Ratchet State Machine & PQ-X3DH
    ├── storage/               <-- Local SQLite History & Session Serialization
    └── net/                   <-- Reactive HTTP & WebSocket Gateway
```

### Module Responsibilities:
1. **`secure-chat-common`**: Contains zero framework dependencies (pure Java 21 + Bouncy Castle). It guarantees that cryptographic logic is 100% portable and reusable across desktop, server, mobile, or CLI environments.
2. **`secure-chat-server`**: Implements Spring Boot 3 enterprise capabilities: declarative transactions, connection pooling (HikariCP), rate limiting, and zero-knowledge persistence. The server does not link or invoke any decryption routines.
3. **`secure-chat-client`**: Executes the user-facing JavaFX GUI, holds local private keys in non-swappable memory buffers, runs the Double Ratchet engine, and executes real-time cryptographic inspection.

---

## 3. Core Protocol Sequence Flows

### 3.1 Client Registration & Key Bundle Publication

```mermaid
sequenceDiagram
    autonumber
    participant Alice as Alice Client
    participant Auth as Server /auth
    participant Keys as Server /keys
    participant DB as Relational Database

    Alice->>Auth: POST /api/v1/auth/register {username, email, password}
    Auth->>DB: INSERT INTO users (hash password with BCrypt)
    Auth-->>Alice: 201 Created

    Alice->>Auth: POST /api/v1/auth/login {username, password}
    Auth-->>Alice: 200 OK {JWT Bearer Token}

    Note over Alice: Generates ML-DSA-65 Identity Keypair (IK)<br/>Generates ML-KEM-768 Signed Prekey (SPK)<br/>Signs SPK using IK private key<br/>Generates 100 ML-KEM-768 One-Time Prekeys (OPK_1..100)
    Alice->>Keys: POST /api/v1/keys/bundle {IK, SPK, Sig, [OPK_1..100]} (Bearer Token)
    Keys->>DB: INSERT INTO user_key_bundles & one_time_prekeys
    Keys->>DB: INSERT INTO audit_logs (KEY_UPLOAD)
    Keys-->>Alice: 201 Created (Bundle Version 1 Published)
```

---

### 3.2 PQ-X3DH Session Handshake & First Message Relay

```mermaid
sequenceDiagram
    autonumber
    participant Alice as Alice Client
    participant Keys as Server /keys
    participant Msg as Server /messages
    participant STOMP as Server WebSocket (STOMP)
    participant Bob as Bob Client

    Alice->>Keys: GET /api/v1/keys/bundle/bob
    Keys->>Keys: Synchronize on recipient lock ("bob")
    Keys->>DB: SELECT * FROM one_time_prekeys WHERE user_id=bob AND is_consumed=FALSE LIMIT 1
    Keys->>DB: UPDATE one_time_prekeys SET is_consumed=TRUE WHERE id=OPK_1
    Keys-->>Alice: 200 OK {IK_bob, SPK_bob, Sig_bob, OPK_1}

    Note over Alice: 1. Verify Sig_bob with IK_bob<br/>2. Encapsulate SPK_bob -> (CT_spk, SS_spk)<br/>3. Encapsulate OPK_1 -> (CT_opk, SS_opk)<br/>4. IKM = SS_spk || SS_opk<br/>5. Derive SessionKey = HKDF(IKM)<br/>6. Encrypt message with AES-256-GCM<br/>7. Sign envelope with Alice IK_priv
    Alice->>Msg: POST /api/v1/messages {to: "bob", ciphertext, nonce, header=(CT_spk:CT_opk), sig}
    Msg->>Msg: Verify Alice's ML-DSA-65 signature
    Msg->>DB: INSERT INTO messages (status='SENT')
    Msg-->>Alice: 201 Created {status: "SENT"}
    Msg->>STOMP: Broadcast to /topic/messages/bob

    STOMP->>Bob: Deliver Message Envelope
    Note over Bob: 1. Verify Alice signature<br/>2. Decapsulate CT_spk using SPK_priv<br/>3. Decapsulate CT_opk using OPK_priv<br/>4. IKM = SS_spk || SS_opk<br/>5. Derive matching SessionKey = HKDF(IKM)<br/>6. Decrypt ciphertext with AES-256-GCM
    Bob->>Msg: PUT /api/v1/messages/{id}/status {status: "READ"}
    Msg->>DB: UPDATE messages SET status='READ', read_at=NOW()
    Msg->>STOMP: Broadcast Receipt to /topic/receipts/alice
    STOMP-->>Alice: Update Status to READ (Double Blue Check)
```

---

### 3.3 Zero-Knowledge Encrypted File Transfer & IDOR Defense

```mermaid
sequenceDiagram
    autonumber
    participant Alice as Alice Client
    participant Server as Server /attachments
    participant Disk as Physical File Vault
    participant Bob as Bob Client
    participant Eve as Unauthorized Eve

    Note over Alice: File (e.g. 15 MB PDF)<br/>Encrypt via 64 KB streaming chunks<br/>Key = Active Ratchet SessionKey
    Alice->>Server: POST /api/v1/attachments/stream (Multipart: chunked bytes)
    Server->>Server: Generate File UUID = "9a8b7c6d..."<br/>Sanitize filename via SafePathUtils
    Server->>Disk: Stream bytes directly to /vault/9a8b7c6d.enc
    Server->>DB: INSERT INTO attachments (file_id, uploader=alice, recipient=bob)
    Server-->>Alice: 201 Created {fileId: "9a8b7c6d..."}

    Note over Eve: Eve intercepts fileId and attempts download
    Eve->>Server: GET /api/v1/attachments/9a8b7c6d/stream (Bearer Token: Eve)
    Server->>DB: SELECT * FROM attachments WHERE file_id="9a8b7c6d..."
    Server->>Server: Check if "eve" equals uploader or recipient -> FALSE
    Server-->>Eve: 403 Forbidden (IDOR Access Denied)

    Bob->>Server: GET /api/v1/attachments/9a8b7c6d/stream (Bearer Token: Bob)
    Server->>Server: Check if "bob" equals recipient -> TRUE
    Server->>Disk: Open FileInputStream("/vault/9a8b7c6d.enc")
    Server-->>Bob: 200 OK (Chunked HTTP Stream)
    Note over Bob: Decrypt chunks with SessionKey<br/>Reconstruct original file on Bob disk
```

---

### 3.4 Key Rotation & Emergency Invalidation Flow

```mermaid
sequenceDiagram
    autonumber
    participant Alice as Alice Client
    participant Keys as Server /keys
    participant DB as Relational Database

    Note over Alice: Periodic Key Rotation (e.g. after 30 days)<br/>Generates new ML-KEM-768 SPK_v2<br/>Signs SPK_v2 with long-term IK
    Alice->>Keys: POST /api/v1/keys/rotate {newPrekey, signature}
    Keys->>DB: UPDATE user_key_bundles SET is_active=FALSE WHERE user_id=alice
    Keys->>DB: INSERT INTO user_key_bundles (key_version=2, is_active=TRUE)
    Keys->>DB: INSERT INTO audit_logs (KEY_ROTATION)
    Keys-->>Alice: 200 OK {keyVersion: 2}

    Note over Alice: Emergency Device Compromise<br/>User clicks "Emergency Revoke"
    Alice->>Keys: POST /api/v1/keys/revoke {reason: "Device Lost"}
    Keys->>DB: UPDATE user_key_bundles SET is_active=FALSE WHERE user_id=alice
    Keys->>DB: UPDATE one_time_prekeys SET is_consumed=TRUE WHERE user_id=alice
    Keys->>DB: INSERT INTO audit_logs (KEY_REVOCATION)
    Keys-->>Alice: 200 OK {revoked: true}

    Note over Bob: Bob tries to initiate session with Alice
    Bob->>Keys: GET /api/v1/keys/bundle/alice
    Keys-->>Bob: 404 Not Found (Active key bundle revoked)
```
