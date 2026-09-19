# LatticeChat — Post-Quantum Cryptography-Based Secure Messaging Application

[![GitHub Repository](https://img.shields.io/badge/GitHub-MalharBhosale%2FLatticeChat-181717.svg?logo=github)](https://github.com/MalharBhosale/LatticeChat.git)
[![Java 21](https://img.shields.io/badge/Java-21%20LTS-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.4-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![JavaFX](https://img.shields.io/badge/JavaFX-21-blue.svg)](https://openjfx.io/)
[![Bouncy Castle PQC](https://img.shields.io/badge/Bouncy%20Castle%20PQC-1.80-blueviolet.svg)](https://www.bouncycastle.org/)

**LatticeChat** is a production-style academic secure messaging application engineered to protect one-to-one communications against both classical and quantum computing threats (Harvest Now, Decrypt Later).

---

## 1. Cryptographic Stack

| Security Function | Algorithm | Standard / Reference |
| :--- | :--- | :--- |
| **Post-Quantum Key Establishment** | **ML-KEM-768** / **ML-KEM-1024** | NIST FIPS 203 (Module-Lattice KEM) |
| **Post-Quantum Digital Signatures** | **ML-DSA-65** / **ML-DSA-87** | NIST FIPS 204 (Module-Lattice DSA) |
| **Authenticated Symmetric Encryption** | **AES-256-GCM** | NIST SP 800-38D (128-bit tag, fresh 96-bit nonce per operation) |
| **Cryptographic Key Derivation** | **HKDF-SHA256** | RFC 5869 |
| **Password Hashing** | **Argon2id** / **BCrypt** | RFC 9106 / Spring Security Crypto |

---

## 2. Project Architecture

The repository is structured as a clean Maven multi-module architecture:

```
LatticeChat/
├── database/                 # DDL schema (schema.sql) and seed data (data.sql)
├── secure-chat-common/       # Shared interfaces (KeyExchangeService, EncryptionService), DTOs, exceptions
├── secure-chat-server/       # Spring Boot 3 REST API, WebSocket (STOMP), JPA, Security backend
└── secure-chat-client/       # JavaFX desktop client application with modern dark UI & Security Dashboard
```

---

## 3. Database Schema & Zero-Knowledge Architecture

The persistence layer (`secure-chat-server` via Spring Data JPA and MySQL 8.0) enforces zero-knowledge storage:

```
                        ┌───────────────────┐
                        │       users       │
                        ├───────────────────┤
                        │ id (PK)           │
                        │ username (UQ)     │
                        │ email (UQ)        │
                        │ password_hash     │
                        └─────────┬─────────┘
                                  │ 1
                 ┌────────────────┼────────────────┐
                 │ 1..*           │ 1..*           │ 1..*
        ┌────────┴────────┐ ┌─────┴─────┐ ┌────────┴────────┐
        │user_key_bundles │ │  messages │ │one_time_prekeys │
        ├─────────────────┤ ├───────────┤ ├─────────────────┤
        │ user_id (FK)    │ │ sender_id │ │ user_id (FK)    │
        │ identity_key    │ │ recip_id  │ │ key_id          │
        │ prekey          │ │ ciphertext│ │ public_key      │
        │ prekey_signature│ │ nonce     │ │ is_consumed     │
        │ is_active       │ │ signature │ └─────────────────┘
        └─────────────────┘ └───────────┘
```

### Critical Security Properties:
1. **No Plaintext Messages**: The `messages` table only stores AES-256-GCM ciphertexts, 96-bit nonces, and sender ML-DSA-65 digital signatures.
2. **Client Key Custody**: Private keys are generated and held strictly on client devices and are never transmitted to or stored on the server.
3. **PQC Sized Columns**: Columns holding ML-KEM public keys (~1.6 KB Base64) and ML-DSA signatures (~4.4 KB Base64) use `TEXT` / `LONGTEXT` to prevent truncation.
4. **Asynchronous Key Exchange**: `one_time_prekeys` supports offline PQ-X3DH style message establishment.
5. **Audit Logging**: `audit_logs` records authentication, key rotations, replay attempts, and anomaly detections.

---

## 4. Getting Started

### Prerequisites
- **JDK 21+**
- **Apache Maven 3.9+**
- **MySQL 8.0+**

### Build the entire project:
```bash
mvn clean install
```

### Run Tests:
```bash
mvn clean test
```

### Run the Spring Boot Backend:
```bash
cd secure-chat-server
mvn spring-boot:run
```

### Run the JavaFX Desktop Client:
```bash
cd secure-chat-client
mvn javafx:run
```

---

## 5. Repository & License

- **GitHub Repository**: [MalharBhosale/LatticeChat](https://github.com/MalharBhosale/LatticeChat.git)
- **License**: MIT
