package com.securechat.common.crypto;

import com.securechat.common.crypto.benchmark.PqcBenchmarkRunner;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PqcSessionBenchmarkTest {

    @Test
    @DisplayName("PQ-X3DH Handshake Benchmark executes all cryptographic phases with sub-50ms latency")
    void testPqX3dhHandshakeBenchmark() {
        PqcBenchmarkRunner runner = new PqcBenchmarkRunner(5, 10);
        PqcBenchmarkRunner.SessionHandshakeBenchmarkResult result = runner.benchmarkPqX3dhHandshake();

        assertNotNull(result, "Session handshake result should not be null");
        assertEquals("PQ-X3DH (ML-KEM-768 + ML-DSA-65 + HKDF)", result.protocol());

        // Assert wire overhead
        assertEquals(6669, result.transmittedBytes(), "Handshake wire payload must equal 6,669 bytes (1184+1088+1088+3309)");

        // Assert individual phases execute cleanly
        assertTrue(result.aliceKeyGenMicros() > 0, "Alice keygen time must be positive");
        assertTrue(result.encapSpkMicros() > 0, "Alice SPK encap time must be positive");
        assertTrue(result.encapOpkMicros() > 0, "Alice OPK encap time must be positive");
        assertTrue(result.derivationMicros() > 0, "Alice HKDF derivation time must be positive");
        assertTrue(result.signMicros() > 0, "Alice signature time must be positive");
        assertTrue(result.verifyMicros() > 0, "Bob verify time must be positive");
        assertTrue(result.bobDecapMicros() > 0, "Bob decapsulation time must be positive");

        // Total handshake latency should easily be sub-50ms on modern hardware
        assertTrue(result.totalHandshakeMicros() > 0, "Total handshake latency must be positive");
        assertTrue(result.totalHandshakeMicros() < 50_000, "Total handshake latency should be well under 50ms");
    }

    @Test
    @DisplayName("PqcBenchmarkRunner report formatters include PQ-X3DH session telemetry")
    void testReportIncludesSessionTelemetry() {
        PqcBenchmarkRunner runner = new PqcBenchmarkRunner(2, 5);
        PqcBenchmarkRunner.BenchmarkSuiteReport report = runner.runAll();

        assertNotNull(report.sessionHandshakeResult());
        String console = runner.formatConsoleReport(report);
        String markdown = runner.formatMarkdownReport(report);

        assertTrue(console.contains("End-to-End Session Handshake Latency (PQ-X3DH)"));
        assertTrue(markdown.contains("PQ-X3DH (ML-KEM-768 + ML-DSA-65 + HKDF)"));
        assertTrue(markdown.contains("Alice Ephemeral KEM KeyGen"));
    }
}
