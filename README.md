# SecureChat — Post-Quantum Cryptography-Based Secure Messaging Application

[![Java 21](https://img.shields.io/badge/Java-21%20LTS-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.4-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![JavaFX](https://img.shields.io/badge/JavaFX-21-blue.svg)](https://openjfx.io/)
[![Bouncy Castle PQC](https://img.shields.io/badge/Bouncy%20Castle%20PQC-1.80-blueviolet.svg)](https://www.bouncycastle.org/)

SecureChat is a modern, modular, production-style academic secure messaging application engineered to protect one-to-one communications against both classical and quantum computing threats.

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

The repository is structured as a Maven multi-module architecture:

```
secure-chat/
├── secure-chat-common/       # Shared interfaces (KeyExchangeService, EncryptionService, etc.), DTOs, exceptions
├── secure-chat-server/       # Spring Boot 3 REST API, WebSocket (STOMP), JPA, Security backend
└── secure-chat-client/       # JavaFX desktop client application with modern dark UI & Security Dashboard
```

---

## 3. Getting Started

### Prerequisites
- **JDK 21+**
- **Apache Maven 3.9+**
- **MySQL 8.0+**

### Build the entire project:
```bash
mvn clean install
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
