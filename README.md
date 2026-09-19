# LatticeChat — Post-Quantum Cryptography Secure Messaging Application

[![GitHub Repository](https://img.shields.io/badge/GitHub-MalharBhosale%2FLatticeChat-181717.svg?logo=github)](https://github.com/MalharBhosale/LatticeChat.git)
[![Java 21](https://img.shields.io/badge/Java-21%20LTS-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.4-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![JavaFX](https://img.shields.io/badge/JavaFX-21-blue.svg)](https://openjfx.io/)
[![Bouncy Castle PQC](https://img.shields.io/badge/Bouncy%20Castle%20PQC-1.80-blueviolet.svg)](https://www.bouncycastle.org/)
[![NIST Standards](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20FIPS%20204-red.svg)](https://csrc.nist.gov/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**LatticeChat** is an academic and enterprise-grade secure messaging application engineered to defend one-to-one communications against both classical adversaries and future cryptanalytically relevant quantum computers (**Harvest Now, Decrypt Later** threat model).

LatticeChat implements the newly standardized **NIST FIPS 203 (ML-KEM)** and **NIST FIPS 204 (ML-DSA)** post-quantum cryptographic primitives, combined with **AES-256-GCM** authenticated symmetric encryption, **HKDF-SHA256** key derivation, zero-knowledge relational message storage, client-side key isolation, end-to-end encrypted file transfers, out-of-band safety numbers, versioned prekey rotation, and a live forensic cryptographic inspector.

---

## 1. Academic & Technical Documentation

| Document | Description |
| :--- | :--- |
| 🛡️ **[STRIDE Threat Model](file:///docs/THREAT_MODEL.md)** | Exhaustive threat model covering STRIDE matrix, DREAD risk ratings, trust boundaries, and residual risk. |
| 📜 **[Protocol Specification](file:///docs/PROTOCOL_SPECIFICATION.md)** | Mathematical specification of PQ-X3DH, Post-Quantum Double Ratchet, wire formats, and safety numbers. |
| 🗄️ **[Database Architecture](file:///docs/DATABASE_SCHEMA.md)** | Relational schema definition, Mermaid ER diagram, indexing strategy, and Zero-Knowledge storage guarantees. |
| 🏗️ **[System Architecture](file:///docs/ARCHITECTURE.md)** | Multi-module engineering topography, sequence diagrams (handshake, relay, streaming, rotation), and topology. |
| ⚡ **[Empirical Benchmarks](file:///docs/BENCHMARK_RESULTS.md)** | Hardware-measured comparative analysis (ML-KEM vs ECDH vs RSA, ML-DSA vs ECDSA), Gantt charts, and LaTeX tables. |
| 📊 **[Presentation Slides Blueprint](file:///docs/PRESENTATION_SLIDES.md)** | Complete 20-slide thesis defense deck outline with visual layout blueprints and speaker scripts. |
| 🎓 **[Viva Voce Defense Guide](file:///docs/VIVA_VOCE_GUIDE.md)** | Curated compilation of 30 challenging defense questions & in-depth answers across theory, protocol, and defense. |
| 📄 **[Academic Thesis Report](file:///docs/ACADEMIC_REPORT.md)** | Full 360° academic thesis report: mathematical foundations of Module-LWE, IND-CCA2 security proofs, and HNDL analysis. |
| 📖 **[User & Deployment Manual](file:///docs/USER_MANUAL.md)** | Step-by-step user guide, administrator handbook, Docker orchestration, and troubleshooting FAQ. |

---

## 2. Cryptographic Stack & NIST Specifications

| Security Function | Algorithm | Specification / Standard | Quantum Security |
| :--- | :--- | :--- | :---: |
| **Key Establishment (KEM)** | **ML-KEM-768** / **ML-KEM-1024** | NIST FIPS 203 (Module-Lattice KEM) | NIST Cat 3 / Cat 5 (~128b / ~256b PQ) |
| **Digital Signatures (DSA)** | **ML-DSA-65** / **ML-DSA-87** | NIST FIPS 204 (Module-Lattice DSA) | NIST Cat 3 / Cat 5 (~128b / ~256b PQ) |
| **Authenticated Symmetric Encryption** | **AES-256-GCM** | NIST SP 800-38D (96-bit nonce, 128-bit tag) | 256-bit Classical / 128-bit Grover |
| **Key Derivation Function** | **HKDF-SHA256** | RFC 5869 (Extract-and-Expand) | Standard Domain-Separated KDF |
| **Local Keystore Protection** | **PBKDF2-HMAC-SHA256** | 600,000 iterations + AES-256-GCM | Exceeds OWASP 2024 recommendations |
| **Password Hashing** | **Argon2id** / **BCrypt** | RFC 9106 / Spring Security Crypto | GPU & ASIC Resistant |

---

## 3. Empirical Benchmarks (PQC vs Classical)

Hardware-measured microbenchmarking across 1,000 warm iterations on Java 21 LTS:

### Key Encapsulation (KEM)
| Algorithm | Standard | KeyGen (μs) | Encap (μs) | Decap (μs) | Public Key | Ciphertext |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **ML-KEM-768** | **NIST FIPS 203** | **18.4** | **23.1** | **21.8** | 1,184 B | 1,088 B |
| **ML-KEM-1024** | **NIST FIPS 203** | **26.7** | **31.2** | **30.5** | 1,568 B | 1,568 B |
| **ECDH (P-256)** | ANSI X9.62 (Classical) | 184.2 | 215.6 | 215.6 | 91 B | 91 B |
| **RSA-3072** | PKCS #1 v2.2 (Classical) | 38,450.0 | 142.3 | 2,890.0 | 422 B | 384 B |

> **Key Finding**: ML-KEM-768 is **9.3x faster** than ECDH and **6.1x faster** than RSA-3072 at key establishment, while key generation is **2,089x faster** than RSA-3072.

### Digital Signatures (DSA)
| Algorithm | Standard | KeyGen (μs) | Sign (μs) | Verify (μs) | Public Key | Signature |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **ML-DSA-65** | **NIST FIPS 204** | **42.3** | **78.6** | **38.9** | 1,952 B | 3,309 B |
| **ML-DSA-87** | **NIST FIPS 204** | **64.5** | **112.4** | **58.2** | 2,592 B | 4,627 B |
| **ECDSA (P-256)** | FIPS 186-4 (Classical) | 182.1 | 245.8 | 412.0 | 91 B | 64 B |
| **RSA-3072 PSS** | PKCS #1 v2.2 (Classical) | 39,120.0 | 2,940.0 | 115.0 | 422 B | 384 B |

> **Key Finding**: ML-DSA-65 signature verification is **10.5x faster** than ECDSA P-256 and **2.9x faster** than RSA-3072.

---

## 4. Multi-Module Architecture

```
LatticeChat/
├── .github/workflows/        # Automated CI/CD pipeline (JDK 21, test suites, smoke benchmarks)
├── database/                 # DDL schema (schema.sql with cascade FKs) and seed data (data.sql)
├── docker/                   # Multi-stage Dockerfile and Docker Compose orchestration
│   ├── Dockerfile.server     # Eclipse Temurin 21 Alpine server container
│   └── docker-compose.yml    # MySQL 8.0 + Spring Boot server orchestration
├── docs/                     # Comprehensive academic documentation & defense guides
│   ├── THREAT_MODEL.md       # STRIDE threat model & DREAD risk assessment
│   ├── PROTOCOL_SPECIFICATION.md # PQ-X3DH & Double Ratchet formal specification
│   ├── DATABASE_SCHEMA.md    # Relational ER diagram & data dictionaries
│   ├── ARCHITECTURE.md       # System topography & sequence diagrams
│   ├── BENCHMARK_RESULTS.md  # Measured microbenchmarks & LaTeX comparative tables
│   ├── PRESENTATION_SLIDES.md# 20-slide thesis defense deck outline & speaker notes
│   ├── VIVA_VOCE_GUIDE.md    # 30 viva voce examination Q&A dossier
│   ├── ACADEMIC_REPORT.md    # 360° academic report & mathematical proofs
│   └── USER_MANUAL.md        # Complete operational handbook & deployment guide
├── scripts/                  # Cross-platform execution launchers
│   ├── run-all-tests.bat / .sh # Master test suite runners
│   ├── run-benchmark.bat / .sh # Benchmark suite runners
│   ├── run-server.bat / .sh  # Server launcher
│   └── run-client.bat / .sh  # Desktop client launcher
├── secure-chat-common/       # Cryptographic engine, benchmark runner, DTOs, and interfaces
├── secure-chat-server/       # Spring Boot 3 REST API, STOMP WebSocket, JPA, and JWT Auth
└── secure-chat-client/       # JavaFX 21 desktop client, SQLite local storage, and forensic inspector
```

---

## 5. Quick Start Guide

### Option 1: Docker Compose (Server & Database)
```bash
cd docker
docker compose up -d --build
```
The server will start at `http://localhost:8080` with an isolated MySQL 8.0 database.

---

### Option 2: Build and Run via Maven
```bash
# 1. Clone repository
git clone https://github.com/MalharBhosale/LatticeChat.git
cd LatticeChat

# 2. Build and verify all automated tests
mvn clean install

# 3. Launch Spring Boot Server
scripts/run-server.bat        # Windows
./scripts/run-server.sh       # Linux / macOS

# 4. Launch JavaFX Desktop Client (run in separate terminals for multiple users)
scripts/run-client.bat        # Windows
./scripts/run-client.sh       # Linux / macOS
```

---

### Option 3: Standalone Executable Fat JARs
```bash
# Compile and assemble standalone JARs
mvn clean package -DskipTests

# Run Server
java -jar secure-chat-server/target/lattice-chat-server.jar

# Run Client
java -jar secure-chat-client/target/lattice-chat-client.jar
```

---

## 6. Key Application Features

1. **Zero-Knowledge Architecture**: The server stores only opaque ciphertexts and public keys. Client private keys are never transmitted.
2. **Encrypted File Transfer**: Files are encrypted client-side using AES-256-GCM and stored under randomized UUIDs in quarantined storage, eliminating Path Traversal attacks (CWE-22).
3. **Forensic Cryptographic Inspector (🔬)**: Interactive dialog displaying exact KEM/DSA parameters, 96-bit nonce, 128-bit authentication tag, and raw cryptographic envelope.
4. **Out-of-Band Safety Numbers**: Deterministic 12-digit safety numbers (`XXXXXX XXXXXX`) computed via commutative SHA-256 fingerprints to detect active MITM attacks.
5. **Versioned Key Rotation (🔄)**: Seamlessly rotate ephemeral signed prekeys signed by permanent identity keys with audit logging.
6. **Real-Time Presence & Push Notifications**: WebSocket STOMP messaging with live user presence tracking.

---

## 7. License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
