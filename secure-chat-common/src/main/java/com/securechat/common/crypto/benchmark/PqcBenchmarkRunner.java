package com.securechat.common.crypto.benchmark;

import com.securechat.common.crypto.EncryptionService;
import com.securechat.common.crypto.KeyExchangeService;
import com.securechat.common.crypto.SignatureService;
import com.securechat.common.crypto.impl.AesGcmEncryptionService;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

/**
 * High-precision microbenchmarking harness for Post-Quantum Cryptography (PQC)
 * vs Classical Cryptography baselines.
 *
 * Evaluates:
 * 1. Key Encapsulation: ML-KEM-768, ML-KEM-1024, ECDH (P-256), RSA-3072.
 * 2. Digital Signatures: ML-DSA-65, ML-DSA-87, ECDSA (P-256), RSA-3072.
 * 3. Authenticated Symmetric Encryption: AES-256-GCM (1 KB, 64 KB, 1 MB).
 *
 * Produces structured results in Console, Markdown, and LaTeX formats
 * suitable for academic thesis publication and defense presentation.
 */
public class PqcBenchmarkRunner {

    public record KemBenchmarkResult(
            String algorithm,
            String standard,
            int quantumSecurityCategory,
            double keyGenMicros,
            double encapMicros,
            double decapMicros,
            int publicKeyBytes,
            int privateKeyBytes,
            int ciphertextBytes,
            int sharedSecretBytes
    ) {}

    public record DsaBenchmarkResult(
            String algorithm,
            String standard,
            int quantumSecurityCategory,
            double keyGenMicros,
            double signMicros,
            double verifyMicros,
            int publicKeyBytes,
            int privateKeyBytes,
            int signatureBytes
    ) {}

    public record SymmetricBenchmarkResult(
            String algorithm,
            int payloadBytes,
            double encryptMicros,
            double decryptMicros,
            double throughputMbps
    ) {}

    public record BenchmarkSuiteReport(
            List<KemBenchmarkResult> kemResults,
            List<DsaBenchmarkResult> dsaResults,
            List<SymmetricBenchmarkResult> symmetricResults,
            int iterations,
            String cpuModel,
            String javaVersion
    ) {}

    private final int warmupIterations;
    private final int measurementIterations;

    public PqcBenchmarkRunner() {
        this(50, 200);
    }

    public PqcBenchmarkRunner(int warmupIterations, int measurementIterations) {
        this.warmupIterations = warmupIterations;
        this.measurementIterations = measurementIterations;
    }

    public static void main(String[] args) {
        System.out.println("===============================================================");
        System.out.println("  LatticeChat Post-Quantum Cryptography Benchmarking Suite     ");
        System.out.println("===============================================================");
        PqcBenchmarkRunner runner = new PqcBenchmarkRunner(100, 500);
        BenchmarkSuiteReport report = runner.runAll();
        System.out.println(runner.formatConsoleReport(report));
        System.out.println("\n--- Markdown Report ---\n");
        System.out.println(runner.formatMarkdownReport(report));
    }

    public BenchmarkSuiteReport runAll() {
        List<KemBenchmarkResult> kemResults = benchmarkKem();
        List<DsaBenchmarkResult> dsaResults = benchmarkDsa();
        List<SymmetricBenchmarkResult> symmetricResults = benchmarkSymmetric();

        String javaVersion = System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")";
        String cpuModel = System.getProperty("os.arch") + " with " + Runtime.getRuntime().availableProcessors() + " cores";

        return new BenchmarkSuiteReport(
                kemResults,
                dsaResults,
                symmetricResults,
                measurementIterations,
                cpuModel,
                javaVersion
        );
    }

    // =========================================================================
    // 1. KEM Benchmarking (ML-KEM vs ECDH vs RSA)
    // =========================================================================

    public List<KemBenchmarkResult> benchmarkKem() {
        List<KemBenchmarkResult> results = new ArrayList<>();
        results.add(benchmarkPqcKem(MlKemKeyExchangeService.mlKem768(), "ML-KEM-768", "NIST FIPS 203", 3));
        results.add(benchmarkPqcKem(MlKemKeyExchangeService.mlKem1024(), "ML-KEM-1024", "NIST FIPS 203", 5));
        results.add(benchmarkEcdhP256());
        results.add(benchmarkRsa3072Kem());
        return results;
    }

    private KemBenchmarkResult benchmarkPqcKem(KeyExchangeService kemService, String name, String standard, int category) {
        // Warmup
        for (int i = 0; i < warmupIterations; i++) {
            KeyExchangeService.KemKeyPair kp = kemService.generateKeyPair();
            KeyExchangeService.KemSecret enc = kemService.encapsulate(kp.publicKey());
            kemService.decapsulate(kp.privateKey(), enc.encapsulationCiphertext());
        }

        long totalKeyGen = 0;
        long totalEncap = 0;
        long totalDecap = 0;

        KeyExchangeService.KemKeyPair sampleKp = kemService.generateKeyPair();
        KeyExchangeService.KemSecret sampleEncap = kemService.encapsulate(sampleKp.publicKey());

        for (int i = 0; i < measurementIterations; i++) {
            long t0 = System.nanoTime();
            KeyExchangeService.KemKeyPair kp = kemService.generateKeyPair();
            long t1 = System.nanoTime();
            totalKeyGen += (t1 - t0);

            long t2 = System.nanoTime();
            KeyExchangeService.KemSecret enc = kemService.encapsulate(kp.publicKey());
            long t3 = System.nanoTime();
            totalEncap += (t3 - t2);

            long t4 = System.nanoTime();
            kemService.decapsulate(kp.privateKey(), enc.encapsulationCiphertext());
            long t5 = System.nanoTime();
            totalDecap += (t5 - t4);
        }

        return new KemBenchmarkResult(
                name,
                standard,
                category,
                (totalKeyGen / (double) measurementIterations) / 1000.0,
                (totalEncap / (double) measurementIterations) / 1000.0,
                (totalDecap / (double) measurementIterations) / 1000.0,
                sampleKp.publicKey().length,
                sampleKp.privateKey().length,
                sampleEncap.encapsulationCiphertext().length,
                sampleEncap.sharedSecret().length
        );
    }

    private KemBenchmarkResult benchmarkEcdhP256() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));

            // Warmup
            for (int i = 0; i < warmupIterations; i++) {
                KeyPair kpA = kpg.generateKeyPair();
                KeyPair kpB = kpg.generateKeyPair();
                KeyAgreement kaA = KeyAgreement.getInstance("ECDH");
                kaA.init(kpA.getPrivate());
                kaA.doPhase(kpB.getPublic(), true);
                kaA.generateSecret();
            }

            long totalKeyGen = 0;
            long totalAgree = 0;
            KeyPair sampleA = kpg.generateKeyPair();
            KeyPair sampleB = kpg.generateKeyPair();

            for (int i = 0; i < measurementIterations; i++) {
                long t0 = System.nanoTime();
                KeyPair kpA = kpg.generateKeyPair();
                KeyPair kpB = kpg.generateKeyPair();
                long t1 = System.nanoTime();
                totalKeyGen += (t1 - t0) / 2;

                long t2 = System.nanoTime();
                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                ka.init(kpA.getPrivate());
                ka.doPhase(kpB.getPublic(), true);
                byte[] secret = ka.generateSecret();
                long t3 = System.nanoTime();
                totalAgree += (t3 - t2);
            }

            double avgKeyGen = (totalKeyGen / (double) measurementIterations) / 1000.0;
            double avgAgree = (totalAgree / (double) measurementIterations) / 1000.0;

            return new KemBenchmarkResult(
                    "ECDH (P-256)",
                    "ANSI X9.62 (Classical)",
                    0,
                    avgKeyGen,
                    avgAgree,
                    avgAgree, // symmetric agreement
                    sampleA.getPublic().getEncoded().length,
                    sampleA.getPrivate().getEncoded().length,
                    sampleB.getPublic().getEncoded().length, // public key exchanged
                    32 // 256-bit secret
            );
        } catch (Exception e) {
            throw new RuntimeException("ECDH benchmark error: " + e.getMessage(), e);
        }
    }

    private KemBenchmarkResult benchmarkRsa3072Kem() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(3072);

            KeyPair sampleKp = kpg.generateKeyPair();
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            byte[] dummySecret = new byte[32];
            new SecureRandom().nextBytes(dummySecret);

            // Warmup
            for (int i = 0; i < Math.min(warmupIterations, 20); i++) {
                cipher.init(Cipher.ENCRYPT_MODE, sampleKp.getPublic());
                byte[] ct = cipher.doFinal(dummySecret);
                cipher.init(Cipher.DECRYPT_MODE, sampleKp.getPrivate());
                cipher.doFinal(ct);
            }

            long totalKeyGen = 0;
            long totalEncap = 0;
            long totalDecap = 0;
            int rsaIters = Math.min(measurementIterations, 50); // RSA-3072 keygen is computationally expensive

            cipher.init(Cipher.ENCRYPT_MODE, sampleKp.getPublic());
            byte[] sampleCt = cipher.doFinal(dummySecret);

            for (int i = 0; i < rsaIters; i++) {
                long t0 = System.nanoTime();
                KeyPair kp = kpg.generateKeyPair();
                long t1 = System.nanoTime();
                totalKeyGen += (t1 - t0);

                long t2 = System.nanoTime();
                cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
                byte[] ct = cipher.doFinal(dummySecret);
                long t3 = System.nanoTime();
                totalEncap += (t3 - t2);

                long t4 = System.nanoTime();
                cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
                cipher.doFinal(ct);
                long t5 = System.nanoTime();
                totalDecap += (t5 - t4);
            }

            return new KemBenchmarkResult(
                    "RSA-3072 OAEP",
                    "PKCS #1 v2.2 (Classical)",
                    0,
                    (totalKeyGen / (double) rsaIters) / 1000.0,
                    (totalEncap / (double) rsaIters) / 1000.0,
                    (totalDecap / (double) rsaIters) / 1000.0,
                    sampleKp.getPublic().getEncoded().length,
                    sampleKp.getPrivate().getEncoded().length,
                    sampleCt.length,
                    32
            );
        } catch (Exception e) {
            throw new RuntimeException("RSA-3072 benchmark error: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // 2. DSA Benchmarking (ML-DSA vs ECDSA vs RSA)
    // =========================================================================

    public List<DsaBenchmarkResult> benchmarkDsa() {
        List<DsaBenchmarkResult> results = new ArrayList<>();
        byte[] samplePayload = "LatticeChat NIST Post-Quantum Cryptographic Protocol Benchmark Envelope".getBytes(StandardCharsets.UTF_8);

        results.add(benchmarkPqcDsa(MlDsaSignatureService.mlDsa65(), "ML-DSA-65", "NIST FIPS 204", 3, samplePayload));
        results.add(benchmarkPqcDsa(MlDsaSignatureService.mlDsa87(), "ML-DSA-87", "NIST FIPS 204", 5, samplePayload));
        results.add(benchmarkEcdsaP256(samplePayload));
        results.add(benchmarkRsa3072Dsa(samplePayload));
        return results;
    }

    private DsaBenchmarkResult benchmarkPqcDsa(SignatureService dsaService, String name, String standard, int category, byte[] message) {
        // Warmup
        for (int i = 0; i < warmupIterations; i++) {
            SignatureService.SignatureKeyPair kp = dsaService.generateKeyPair();
            byte[] sig = dsaService.sign(message, kp.privateKey());
            dsaService.verify(message, sig, kp.publicKey());
        }

        long totalKeyGen = 0;
        long totalSign = 0;
        long totalVerify = 0;

        SignatureService.SignatureKeyPair sampleKp = dsaService.generateKeyPair();
        byte[] sampleSig = dsaService.sign(message, sampleKp.privateKey());

        for (int i = 0; i < measurementIterations; i++) {
            long t0 = System.nanoTime();
            SignatureService.SignatureKeyPair kp = dsaService.generateKeyPair();
            long t1 = System.nanoTime();
            totalKeyGen += (t1 - t0);

            long t2 = System.nanoTime();
            byte[] sig = dsaService.sign(message, kp.privateKey());
            long t3 = System.nanoTime();
            totalSign += (t3 - t2);

            long t4 = System.nanoTime();
            dsaService.verify(message, sig, kp.publicKey());
            long t5 = System.nanoTime();
            totalVerify += (t5 - t4);
        }

        return new DsaBenchmarkResult(
                name,
                standard,
                category,
                (totalKeyGen / (double) measurementIterations) / 1000.0,
                (totalSign / (double) measurementIterations) / 1000.0,
                (totalVerify / (double) measurementIterations) / 1000.0,
                sampleKp.publicKey().length,
                sampleKp.privateKey().length,
                sampleSig.length
        );
    }

    private DsaBenchmarkResult benchmarkEcdsaP256(byte[] message) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair sampleKp = kpg.generateKeyPair();
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(sampleKp.getPrivate());
            signer.update(message);
            byte[] sampleSig = signer.sign();

            // Warmup
            for (int i = 0; i < warmupIterations; i++) {
                signer.initSign(sampleKp.getPrivate());
                signer.update(message);
                byte[] s = signer.sign();
                signer.initVerify(sampleKp.getPublic());
                signer.update(message);
                signer.verify(s);
            }

            long totalKeyGen = 0;
            long totalSign = 0;
            long totalVerify = 0;

            for (int i = 0; i < measurementIterations; i++) {
                long t0 = System.nanoTime();
                KeyPair kp = kpg.generateKeyPair();
                long t1 = System.nanoTime();
                totalKeyGen += (t1 - t0);

                long t2 = System.nanoTime();
                signer.initSign(kp.getPrivate());
                signer.update(message);
                byte[] sig = signer.sign();
                long t3 = System.nanoTime();
                totalSign += (t3 - t2);

                long t4 = System.nanoTime();
                signer.initVerify(kp.getPublic());
                signer.update(message);
                signer.verify(sig);
                long t5 = System.nanoTime();
                totalVerify += (t5 - t4);
            }

            return new DsaBenchmarkResult(
                    "ECDSA (P-256)",
                    "FIPS 186-4 (Classical)",
                    0,
                    (totalKeyGen / (double) measurementIterations) / 1000.0,
                    (totalSign / (double) measurementIterations) / 1000.0,
                    (totalVerify / (double) measurementIterations) / 1000.0,
                    sampleKp.getPublic().getEncoded().length,
                    sampleKp.getPrivate().getEncoded().length,
                    sampleSig.length
            );
        } catch (Exception e) {
            throw new RuntimeException("ECDSA benchmark error: " + e.getMessage(), e);
        }
    }

    private DsaBenchmarkResult benchmarkRsa3072Dsa(byte[] message) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(3072);

            KeyPair sampleKp = kpg.generateKeyPair();
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(sampleKp.getPrivate());
            signer.update(message);
            byte[] sampleSig = signer.sign();

            int rsaIters = Math.min(measurementIterations, 50);

            long totalKeyGen = 0;
            long totalSign = 0;
            long totalVerify = 0;

            for (int i = 0; i < rsaIters; i++) {
                long t0 = System.nanoTime();
                KeyPair kp = kpg.generateKeyPair();
                long t1 = System.nanoTime();
                totalKeyGen += (t1 - t0);

                long t2 = System.nanoTime();
                signer.initSign(kp.getPrivate());
                signer.update(message);
                byte[] sig = signer.sign();
                long t3 = System.nanoTime();
                totalSign += (t3 - t2);

                long t4 = System.nanoTime();
                signer.initVerify(kp.getPublic());
                signer.update(message);
                signer.verify(sig);
                long t5 = System.nanoTime();
                totalVerify += (t5 - t4);
            }

            return new DsaBenchmarkResult(
                    "RSA-3072 PSS",
                    "PKCS #1 v2.2 (Classical)",
                    0,
                    (totalKeyGen / (double) rsaIters) / 1000.0,
                    (totalSign / (double) rsaIters) / 1000.0,
                    (totalVerify / (double) rsaIters) / 1000.0,
                    sampleKp.getPublic().getEncoded().length,
                    sampleKp.getPrivate().getEncoded().length,
                    sampleSig.length
            );
        } catch (Exception e) {
            throw new RuntimeException("RSA-3072 DSA benchmark error: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // 3. Symmetric Encryption Benchmarking (AES-256-GCM)
    // =========================================================================

    public List<SymmetricBenchmarkResult> benchmarkSymmetric() {
        List<SymmetricBenchmarkResult> results = new ArrayList<>();
        AesGcmEncryptionService aes = new AesGcmEncryptionService();
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        int[] payloadSizes = {1024, 64 * 1024, 1024 * 1024}; // 1 KB, 64 KB, 1 MB

        for (int size : payloadSizes) {
            byte[] payload = new byte[size];
            new SecureRandom().nextBytes(payload);

            // Warmup
            for (int i = 0; i < warmupIterations; i++) {
                byte[] enc = aes.encrypt(payload, key, null);
                aes.decrypt(enc, key, null);
            }

            long totalEncrypt = 0;
            long totalDecrypt = 0;

            for (int i = 0; i < measurementIterations; i++) {
                long t0 = System.nanoTime();
                byte[] enc = aes.encrypt(payload, key, null);
                long t1 = System.nanoTime();
                totalEncrypt += (t1 - t0);

                long t2 = System.nanoTime();
                aes.decrypt(enc, key, null);
                long t3 = System.nanoTime();
                totalDecrypt += (t3 - t2);
            }

            double avgEncryptMicros = (totalEncrypt / (double) measurementIterations) / 1000.0;
            double avgDecryptMicros = (totalDecrypt / (double) measurementIterations) / 1000.0;
            double totalSeconds = (totalEncrypt + totalDecrypt) / 1_000_000_000.0;
            double totalMegaBytes = (size * 2.0 * measurementIterations) / (1024.0 * 1024.0);
            double throughput = totalMegaBytes / totalSeconds;

            results.add(new SymmetricBenchmarkResult(
                    "AES-256-GCM",
                    size,
                    avgEncryptMicros,
                    avgDecryptMicros,
                    throughput
            ));
        }

        return results;
    }

    // =========================================================================
    // 4. Report Formatting: Console, Markdown, and LaTeX
    // =========================================================================

    public String formatConsoleReport(BenchmarkSuiteReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Platform: %s | CPU: %s | Measured Iterations: %d\n", report.javaVersion(), report.cpuModel(), report.iterations()));
        sb.append("\n1. Key Encapsulation Mechanisms (KEM):\n");
        sb.append(String.format("%-15s | %-12s | %-12s | %-12s | %-10s | %-10s | %-10s\n",
                "Algorithm", "KeyGen (us)", "Encap (us)", "Decap (us)", "PK (bytes)", "SK (bytes)", "CT (bytes)"));
        sb.append("----------------------------------------------------------------------------------------------------\n");
        for (KemBenchmarkResult r : report.kemResults()) {
            sb.append(String.format("%-15s | %12.2f | %12.2f | %12.2f | %10d | %10d | %10d\n",
                    r.algorithm(), r.keyGenMicros(), r.encapMicros(), r.decapMicros(),
                    r.publicKeyBytes(), r.privateKeyBytes(), r.ciphertextBytes()));
        }

        sb.append("\n2. Digital Signature Algorithms (DSA):\n");
        sb.append(String.format("%-15s | %-12s | %-12s | %-12s | %-10s | %-10s | %-10s\n",
                "Algorithm", "KeyGen (us)", "Sign (us)", "Verify (us)", "PK (bytes)", "SK (bytes)", "Sig (bytes)"));
        sb.append("----------------------------------------------------------------------------------------------------\n");
        for (DsaBenchmarkResult r : report.dsaResults()) {
            sb.append(String.format("%-15s | %12.2f | %12.2f | %12.2f | %10d | %10d | %10d\n",
                    r.algorithm(), r.keyGenMicros(), r.signMicros(), r.verifyMicros(),
                    r.publicKeyBytes(), r.privateKeyBytes(), r.signatureBytes()));
        }

        sb.append("\n3. Authenticated Symmetric Encryption (AES-256-GCM):\n");
        sb.append(String.format("%-15s | %-12s | %-12s | %-12s | %-18s\n",
                "Algorithm", "Payload Size", "Encrypt (us)", "Decrypt (us)", "Throughput (MB/s)"));
        sb.append("--------------------------------------------------------------------------------\n");
        for (SymmetricBenchmarkResult r : report.symmetricResults()) {
            String sizeStr = r.payloadBytes() < 1024 * 1024 ? (r.payloadBytes() / 1024) + " KB" : (r.payloadBytes() / (1024 * 1024)) + " MB";
            sb.append(String.format("%-15s | %-12s | %12.2f | %12.2f | %18.2f\n",
                    r.algorithm(), sizeStr, r.encryptMicros(), r.decryptMicros(), r.throughputMbps()));
        }
        return sb.toString();
    }

    public String formatMarkdownReport(BenchmarkSuiteReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("### Post-Quantum Key Encapsulation (KEM) Benchmarks\n\n");
        sb.append("| Algorithm | Standard | Category | KeyGen (μs) | Encap (μs) | Decap (μs) | Public Key | Private Key | Ciphertext |\n");
        sb.append("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n");
        for (KemBenchmarkResult r : report.kemResults()) {
            sb.append(String.format("| **%s** | %s | %d | `%.1f` | `%.1f` | `%.1f` | %d B | %d B | %d B |\n",
                    r.algorithm(), r.standard(), r.quantumSecurityCategory(),
                    r.keyGenMicros(), r.encapMicros(), r.decapMicros(),
                    r.publicKeyBytes(), r.privateKeyBytes(), r.ciphertextBytes()));
        }

        sb.append("\n### Post-Quantum Digital Signature (DSA) Benchmarks\n\n");
        sb.append("| Algorithm | Standard | Category | KeyGen (μs) | Sign (μs) | Verify (μs) | Public Key | Private Key | Signature |\n");
        sb.append("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n");
        for (DsaBenchmarkResult r : report.dsaResults()) {
            sb.append(String.format("| **%s** | %s | %d | `%.1f` | `%.1f` | `%.1f` | %d B | %d B | %d B |\n",
                    r.algorithm(), r.standard(), r.quantumSecurityCategory(),
                    r.keyGenMicros(), r.signMicros(), r.verifyMicros(),
                    r.publicKeyBytes(), r.privateKeyBytes(), r.signatureBytes()));
        }

        sb.append("\n### Authenticated Symmetric Encryption (AES-256-GCM)\n\n");
        sb.append("| Algorithm | Payload Size | Encryption Latency (μs) | Decryption Latency (μs) | Throughput (MB/s) |\n");
        sb.append("| :--- | :---: | :---: | :---: | :---: |\n");
        for (SymmetricBenchmarkResult r : report.symmetricResults()) {
            String sizeStr = r.payloadBytes() < 1024 * 1024 ? (r.payloadBytes() / 1024) + " KB" : (r.payloadBytes() / (1024 * 1024)) + " MB";
            sb.append(String.format("| **%s** | %s | `%.1f` | `%.1f` | **%.2f MB/s** |\n",
                    r.algorithm(), sizeStr, r.encryptMicros(), r.decryptMicros(), r.throughputMbps()));
        }
        return sb.toString();
    }

    public String formatLatexReport(BenchmarkSuiteReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("% LaTeX Table: KEM Comparison\n");
        sb.append("\\begin{table}[h!]\n\\centering\n\\small\n");
        sb.append("\\begin{tabular}{l c c c c c c}\n\\hline\n");
        sb.append("Algorithm & Standard & KeyGen ($\\mu s$) & Encap ($\\mu s$) & Decap ($\\mu s$) & PK (B) & CT (B) \\\\ \\hline\n");
        for (KemBenchmarkResult r : report.kemResults()) {
            sb.append(String.format("%s & %s & %.1f & %.1f & %.1f & %d & %d \\\\\n",
                    r.algorithm(), r.standard().replace("#", "\\#"),
                    r.keyGenMicros(), r.encapMicros(), r.decapMicros(),
                    r.publicKeyBytes(), r.ciphertextBytes()));
        }
        sb.append("\\hline\n\\end{tabular}\n\\caption{Key Encapsulation Mechanism Performance Evaluation}\n\\label{tab:kem_benchmark}\n\\end{table}\n");
        return sb.toString();
    }
}
