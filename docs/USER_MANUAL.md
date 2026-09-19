# LatticeChat: User & Deployment Manual

**A complete operational handbook for running, configuring, and testing LatticeChat.**

---

## 1. System Requirements & Prerequisites

### Minimum System Specifications
- **Operating System**: Windows 10/11 (64-bit), Linux (Ubuntu 20.04+, Debian 11+, Fedora 38+), or macOS 12+ (Apple Silicon or Intel).
- **Java Development Kit (JDK)**: **Java 21 LTS** or newer (Eclipse Temurin, Oracle OpenJDK, or Amazon Corretto).
- **Build Tool**: **Apache Maven 3.9+**.
- **Database**: **MySQL 8.0+** (or Docker for containerized deployment).
- **Memory**: Minimum 4 GB RAM (8 GB recommended for running both server and multiple client instances).

---

## 2. Quick-Start Deployment Options

### Option A: Complete Docker Compose Orchestration (Recommended for Server)
Deploy MySQL 8.0 and LatticeChat Server with a single command:

```bash
cd docker
docker compose up -d --build
```

- **Server URL**: `http://localhost:8080`
- **MySQL Port**: `3306` (Database: `securechat_db`)
- To view logs:
  ```bash
  docker compose logs -f server
  ```
- To shut down:
  ```bash
  docker compose down
  ```

---

### Option B: Local Maven Execution (Developer Mode)

#### 1. Setup Database
Ensure MySQL 8.0 is running locally on port 3306. Execute the schema initialization:
```sql
CREATE DATABASE IF NOT EXISTS securechat_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```
*(Tables and initial seed users are automatically populated on first server startup via JPA and schema scripts).*

#### 2. Run the Spring Boot Server
In a terminal window:
```bash
# On Windows
scripts\run-server.bat

# On Linux / macOS
chmod +x scripts/run-server.sh
./scripts/run-server.sh

# Or directly via Maven:
mvn spring-boot:run -pl secure-chat-server
```
The server will start on `http://localhost:8080`.

#### 3. Run the JavaFX Desktop Client
In a separate terminal window:
```bash
# On Windows
scripts\run-client.bat

# On Linux / macOS
chmod +x scripts/run-client.sh
./scripts/run-client.sh

# Or directly via Maven:
mvn javafx:run -pl secure-chat-client
```

---

### Option C: Standalone Runnable Fat JAR Execution (Production Distribution)

Compile and package all modules into standalone executable JARs:
```bash
mvn clean package -DskipTests
```

This generates:
- **Server JAR**: `secure-chat-server/target/lattice-chat-server.jar`
- **Client Fat JAR**: `secure-chat-client/target/lattice-chat-client.jar`

#### Launch Server:
```bash
java -jar secure-chat-server/target/lattice-chat-server.jar
```

#### Launch Client(s):
```bash
java -jar secure-chat-client/target/lattice-chat-client.jar
```
*(Tip: You can launch multiple instances of the client to test peer-to-peer messaging between Alice and Bob simultaneously).*

---

## 3. End-to-End User Walkthrough

### 3.1 User Registration & Keystore Initialization
1. Launch the Desktop Client.
2. If you don't have an account, click **"Register new account"**.
3. Enter:
   - **Username**: (e.g. `alice` or `bob`)
   - **Email**: (e.g. `alice@latticechat.io`)
   - **Account Password**: (Used for server authentication)
   - **Keystore Master Passphrase**: (Used locally to encrypt your private ML-KEM and ML-DSA keys on disk using PBKDF2 + AES-256-GCM).
4. Click **"Register & Initialize Keystore"**.
5. The client automatically:
   - Generates an **ML-DSA-65** permanent identity key pair.
   - Generates an **ML-KEM-768** signed prekey pair.
   - Signs the prekey with the identity key.
   - Serializes private keys into encrypted `keystore.pqc`.
   - Registers the account and publishes the public key bundle to the server.

### 3.2 Logging In
1. Enter your **Username** and **Account Password**.
2. Enter your **Keystore Passphrase** to unlock your local private keys.
3. Click **"Sign In & Decrypt Keystore"**.
4. Upon successful login, you are redirected to the modern dark chat interface, and the client establishes a secure STOMP over WebSocket connection for real-time presence and message delivery.

### 3.3 Starting a Chat & Sending End-to-End Encrypted Messages
1. In the sidebar, select a contact from the active user list (e.g. click on `bob`).
2. Type a message in the input field at the bottom.
3. Press **Enter** or click the **Send (➤)** button.
4. **Behind the scenes**:
   - The client fetches Bob's public bundle.
   - Verifies Bob's ML-DSA-65 digital signature.
   - Encapsulates an ephemeral shared secret using ML-KEM-768.
   - Derives a 256-bit AES session key using HKDF-SHA256.
   - Encrypts your text with AES-256-GCM.
   - Signs the message envelope with your ML-DSA-65 key.
   - Relays the ciphertext envelope to Bob in real-time over WebSocket.

---

### 3.4 Sending Zero-Knowledge Encrypted File Attachments
1. In an open chat conversation, click the **📎 (Attach File)** button next to the text input.
2. A file selection dialog opens. Select any document, image, or file (up to 25 MB).
3. The client:
   - Encrypts the entire file locally with AES-256-GCM using a fresh 96-bit nonce and 128-bit authentication tag.
   - Uploads the opaque ciphertext blob to the server's quarantined storage.
   - Automatically transmits an encrypted pointer message: `[FILE]:<fileId>:<filename>:<size>:<mime>`.
4. In Bob's chat window, an interactive **Attachment Bubble** appears with a file icon, formatted file size (e.g., `2.4 MB`), and filename.
5. Bob clicks **"⬇ Download & Decrypt"**:
   - Bob selects where to save the file on his computer.
   - The client downloads the ciphertext blob from the server.
   - Decrypts it locally using the session key.
   - Verifies the 128-bit authentication tag to ensure zero corruption or tampering.
   - Restores the exact original file to disk.

---

### 3.5 Real-Time Forensic Cryptographic Inspection (🔬)
1. On **any message bubble** in the chat window, click the **🔬 (Crypto Inspector)** button.
2. A forensic cryptographic inspection dialog opens displaying:
   - **Message ID & Monotonic Sequence Number**: Proves message freshness and order.
   - **Post-Quantum KEM**: NIST FIPS 203 ML-KEM-768 parameter verification.
   - **Digital Signature**: NIST FIPS 204 ML-DSA-65 (3,309-byte signature verification).
   - **Authenticated Encryption**: AES-256-GCM status.
   - **Nonce & Auth Tag**: Exact 96-bit initialization vector and 128-bit GMAC tag displayed in Hex.
   - **12-Digit Out-of-Band Safety Number**: Distinctive peer safety number.
   - **Raw Cryptographic Envelope**: Expandable JSON view of the exact payload transmitted over the wire.

---

### 3.6 Out-of-Band Safety Number Verification
1. Click the **🛡️ Security** button in the chat header or sidebar.
2. The Security Dashboard displays the **12-Digit Safety Number** formatted as two blocks of six numbers (e.g., `482910 739281`).
3. Compare these 12 digits with your contact in person or over an authenticated voice call.
4. If the numbers match exactly, you are guaranteed that no active Machine-in-the-Middle (MITM) or server operator has intercepted or substituted your public keys.

---

### 3.7 On-Demand Post-Quantum Prekey Rotation (🔄)
1. In the Security Dashboard, locate the **"Post-Quantum Key Rotation"** card.
2. Notice your current active key version (e.g. `v1`).
3. Click **"🔄 Rotate Prekey"**.
4. The client:
   - Generates a brand-new ML-KEM-768 key pair.
   - Signs the new prekey with your permanent ML-DSA-65 identity key.
   - Uploads the signed rotation request to `POST /api/v1/keys/rotate`.
   - The server validates the signature, retires the old prekey bundle, and activates the new bundle with an incremented version (`v2`).
   - The UI immediately updates to reflect the active key rotation.

---

## 4. Troubleshooting & FAQ

### Issue: "Port 8080 already in use"
**Solution**:
Run the server on a custom port using the `SERVER_PORT` environment variable:
```bash
java -jar secure-chat-server/target/lattice-chat-server.jar --server.port=9090
```

### Issue: "Failed to connect to MySQL on localhost:3306"
**Solution**:
Verify that MySQL is running:
- Windows: Open Services (`services.msc`) and verify `MySQL80` service is running.
- Linux: Run `sudo systemctl status mysql`.
- Or use the Docker Compose deployment (`cd docker && docker compose up -d`), which starts its own isolated MySQL container automatically.

### Issue: "Invalid Keystore Passphrase"
**Solution**:
The keystore passphrase decrypts your local `keystore.pqc` file via PBKDF2 + AES-GCM. Because LatticeChat is zero-knowledge, the server does not know your keystore passphrase. If you forget your passphrase, you must delete your local `keystore.pqc` and re-register your user keys.

### Issue: "Graphics pipeline initialization warning in JavaFX on Linux"
**Solution**:
On headless Linux environments or systems without hardware acceleration, launch the client with software rendering:
```bash
java -Dprism.order=sw -jar secure-chat-client/target/lattice-chat-client.jar
```
