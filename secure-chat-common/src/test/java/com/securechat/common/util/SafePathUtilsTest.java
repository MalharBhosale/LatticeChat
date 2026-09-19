package com.securechat.common.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SafePathUtilsTest {

    @TempDir
    Path sandboxDir;

    @Test
    @DisplayName("Should sanitize directory traversal sequences and slashes")
    void testSanitizePathTraversal() {
        assertEquals("passwd", SafePathUtils.sanitizeFilename("../../etc/passwd"));
        assertEquals("cmd.exe", SafePathUtils.sanitizeFilename("..\\..\\Windows\\System32\\cmd.exe"));
        assertEquals("report.pdf", SafePathUtils.sanitizeFilename("/var/log/secret/report.pdf"));
        assertEquals("document.docx", SafePathUtils.sanitizeFilename("D:\\Confidential\\document.docx"));
    }

    @Test
    @DisplayName("Should strip null bytes and control characters")
    void testSanitizeNullBytesAndControlChars() {
        assertEquals("testfile.txt", SafePathUtils.sanitizeFilename("test\u0000file.txt"));
        assertEquals("malicious.sh", SafePathUtils.sanitizeFilename("malicious\n\r\t.sh"));
    }

    @Test
    @DisplayName("Should neutralize Windows reserved device names")
    void testNeutralizeWindowsReservedNames() {
        assertEquals("safe_CON.txt", SafePathUtils.sanitizeFilename("CON.txt"));
        assertEquals("safe_con", SafePathUtils.sanitizeFilename("con"));
        assertEquals("safe_NUL.dat", SafePathUtils.sanitizeFilename("NUL.dat"));
        assertEquals("safe_aux", SafePathUtils.sanitizeFilename("aux"));
        assertEquals("safe_COM1.log", SafePathUtils.sanitizeFilename("COM1.log"));
        assertEquals("safe_lpt3", SafePathUtils.sanitizeFilename("lpt3"));
    }

    @Test
    @DisplayName("Should enforce safe default when input is blank, null, or all dots")
    void testDefaultSafeFilename() {
        assertEquals(SafePathUtils.DEFAULT_SAFE_FILENAME, SafePathUtils.sanitizeFilename(null));
        assertEquals(SafePathUtils.DEFAULT_SAFE_FILENAME, SafePathUtils.sanitizeFilename(""));
        assertEquals(SafePathUtils.DEFAULT_SAFE_FILENAME, SafePathUtils.sanitizeFilename("   "));
        assertEquals(SafePathUtils.DEFAULT_SAFE_FILENAME, SafePathUtils.sanitizeFilename("..."));
    }

    @Test
    @DisplayName("Should resolve safe paths strictly inside designated sandbox")
    void testResolveSafePathSuccess() {
        Path resolved = SafePathUtils.resolveSafePath(sandboxDir, "normal_file.pdf");
        assertTrue(resolved.startsWith(sandboxDir));
        assertEquals("normal_file.pdf", resolved.getFileName().toString());
    }

    @Test
    @DisplayName("Should reject and prevent directory escape when resolving paths")
    void testResolveSafePathTraversalAttack() {
        // Even if an attacker attempts relative traversal in resolveSafePath,
        // sanitizeFilename strips traversal so it remains in sandbox
        Path resolved = SafePathUtils.resolveSafePath(sandboxDir, "../../../escape.txt");
        assertTrue(resolved.startsWith(sandboxDir));
        assertEquals("escape.txt", resolved.getFileName().toString());
    }

    @Test
    @DisplayName("Should throw SecurityException when candidate path escapes sandbox in assertSafePath")
    void testAssertSafePathEscapeThrows() {
        Path outsidePath = sandboxDir.resolve("..").resolve("outside.txt").normalize();
        assertThrows(SecurityException.class, () -> SafePathUtils.assertSafePath(sandboxDir, outsidePath));
    }
}
