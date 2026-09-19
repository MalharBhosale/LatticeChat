package com.securechat.common.crypto;

import com.securechat.common.crypto.benchmark.PqcBenchmarkRunner;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PqcBenchmarkTest {

    @Test
    @DisplayName("PQC Microbenchmark Suite executes and validates cryptographic parameter sizes")
    void testBenchmarkSuiteExecution() {
        // Run with small iteration count for fast CI/CD validation
        PqcBenchmarkRunner runner = new PqcBenchmarkRunner(5, 15);
        PqcBenchmarkRunner.BenchmarkSuiteReport report = runner.runAll();

        assertNotNull(report, "Report should not be null");
        assertEquals(4, report.kemResults().size(), "Should benchmark 4 KEM algorithms");
        assertEquals(4, report.dsaResults().size(), "Should benchmark 4 DSA algorithms");
        assertEquals(3, report.symmetricResults().size(), "Should benchmark 3 symmetric payload sizes");

        // Verify ML-KEM-768 parameter sizes (NIST FIPS 203)
        PqcBenchmarkRunner.KemBenchmarkResult mlKem768 = report.kemResults().stream()
                .filter(r -> r.algorithm().equals("ML-KEM-768"))
                .findFirst()
                .orElseThrow();
        assertEquals(1184, mlKem768.publicKeyBytes(), "ML-KEM-768 public key size must be 1184 bytes");
        assertEquals(1088, mlKem768.ciphertextBytes(), "ML-KEM-768 ciphertext size must be 1088 bytes");
        assertEquals(32, mlKem768.sharedSecretBytes(), "ML-KEM-768 shared secret must be 32 bytes (256-bit)");
        assertTrue(mlKem768.encapMicros() > 0, "Encap time should be positive");
        assertTrue(mlKem768.decapMicros() > 0, "Decap time should be positive");

        // Verify ML-KEM-1024 parameter sizes
        PqcBenchmarkRunner.KemBenchmarkResult mlKem1024 = report.kemResults().stream()
                .filter(r -> r.algorithm().equals("ML-KEM-1024"))
                .findFirst()
                .orElseThrow();
        assertEquals(1568, mlKem1024.publicKeyBytes(), "ML-KEM-1024 public key size must be 1568 bytes");
        assertEquals(1568, mlKem1024.ciphertextBytes(), "ML-KEM-1024 ciphertext size must be 1568 bytes");

        // Verify ML-DSA-65 parameter sizes (NIST FIPS 204)
        PqcBenchmarkRunner.DsaBenchmarkResult mlDsa65 = report.dsaResults().stream()
                .filter(r -> r.algorithm().equals("ML-DSA-65"))
                .findFirst()
                .orElseThrow();
        assertEquals(1952, mlDsa65.publicKeyBytes(), "ML-DSA-65 public key size must be 1952 bytes");
        assertEquals(3309, mlDsa65.signatureBytes(), "ML-DSA-65 signature size must be 3309 bytes");
        assertTrue(mlDsa65.signMicros() > 0, "Sign time should be positive");
        assertTrue(mlDsa65.verifyMicros() > 0, "Verify time should be positive");

        // Verify ML-DSA-87 parameter sizes
        PqcBenchmarkRunner.DsaBenchmarkResult mlDsa87 = report.dsaResults().stream()
                .filter(r -> r.algorithm().equals("ML-DSA-87"))
                .findFirst()
                .orElseThrow();
        assertEquals(2592, mlDsa87.publicKeyBytes(), "ML-DSA-87 public key size must be 2592 bytes");
        assertEquals(4627, mlDsa87.signatureBytes(), "ML-DSA-87 signature size must be 4627 bytes");

        // Verify Symmetric AES-256-GCM
        PqcBenchmarkRunner.SymmetricBenchmarkResult aes1mb = report.symmetricResults().stream()
                .filter(r -> r.payloadBytes() == 1024 * 1024)
                .findFirst()
                .orElseThrow();
        assertTrue(aes1mb.throughputMbps() > 10.0, "AES-256-GCM throughput should exceed 10 MB/s");

        // Verify formatting outputs
        String consoleReport = runner.formatConsoleReport(report);
        String markdownReport = runner.formatMarkdownReport(report);
        String latexReport = runner.formatLatexReport(report);

        assertTrue(consoleReport.contains("ML-KEM-768"));
        assertTrue(markdownReport.contains("Post-Quantum Key Encapsulation"));
        assertTrue(latexReport.contains("\\begin{table}"));
    }
}
