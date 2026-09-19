package com.securechat.common.util;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * High-assurance path traversal defense and filename sanitization utility.
 * Guarantees that untrusted filenames supplied across network protocols or local filesystem
 * interfaces cannot break out of designated storage sandboxes or exploit operating system quirks.
 */
public final class SafePathUtils {

    private static final Set<String> WINDOWS_RESERVED_NAMES = Set.of(
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    );

    private static final Pattern ILLEGAL_CHARS = Pattern.compile("[^a-zA-Z0-9._-]");
    private static final int MAX_FILENAME_LENGTH = 128;
    public static final String DEFAULT_SAFE_FILENAME = "attachment.bin";

    private SafePathUtils() {
        // Static utility class
    }

    /**
     * Sanitizes an untrusted filename, stripping directory traversal sequences,
     * null bytes, control characters, and reserved operating system identifiers.
     *
     * @param rawFilename Untrusted input filename
     * @return Cleaned, safe filename
     */
    public static String sanitizeFilename(String rawFilename) {
        if (rawFilename == null || rawFilename.isBlank()) {
            return DEFAULT_SAFE_FILENAME;
        }

        // 1. Remove null bytes and control characters
        String cleaned = rawFilename.replace("\0", "").replaceAll("\\p{Cntrl}", "").trim();

        // 2. Strip directory path separators (both POSIX / and Windows \)
        int lastSlash = Math.max(cleaned.lastIndexOf('/'), cleaned.lastIndexOf('\\'));
        if (lastSlash >= 0) {
            cleaned = cleaned.substring(lastSlash + 1);
        }

        // 3. Remove drive letter colons if present (e.g. C:file.txt)
        int colon = cleaned.lastIndexOf(':');
        if (colon >= 0) {
            cleaned = cleaned.substring(colon + 1);
        }

        // 4. Remove leading periods (hidden files / relative traversal)
        while (cleaned.startsWith(".")) {
            cleaned = cleaned.substring(1);
        }

        // 5. Replace any illegal or shell-sensitive characters with underscores
        cleaned = ILLEGAL_CHARS.matcher(cleaned).replaceAll("_");

        // 6. Neutralize Windows reserved device names (e.g. CON, NUL, AUX, COM1)
        String baseNameWithoutExt = cleaned;
        int dotIdx = cleaned.indexOf('.');
        if (dotIdx >= 0) {
            baseNameWithoutExt = cleaned.substring(0, dotIdx);
        }
        if (WINDOWS_RESERVED_NAMES.contains(baseNameWithoutExt.toUpperCase(Locale.ROOT))) {
            cleaned = "safe_" + cleaned;
        }

        // 7. Enforce maximum length limit while preserving extension
        if (cleaned.length() > MAX_FILENAME_LENGTH) {
            int extDot = cleaned.lastIndexOf('.');
            if (extDot > 0 && extDot < cleaned.length() - 1) {
                String ext = cleaned.substring(extDot);
                int keepLen = MAX_FILENAME_LENGTH - ext.length();
                if (keepLen > 0) {
                    cleaned = cleaned.substring(0, keepLen) + ext;
                } else {
                    cleaned = cleaned.substring(0, MAX_FILENAME_LENGTH);
                }
            } else {
                cleaned = cleaned.substring(0, MAX_FILENAME_LENGTH);
            }
        }

        if (cleaned.isBlank() || cleaned.equals("_")) {
            return DEFAULT_SAFE_FILENAME;
        }

        return cleaned;
    }

    /**
     * Resolves an untrusted filename inside a base directory and verifies that the resulting
     * path does not escape the sandbox boundary.
     *
     * @param baseDirectory Designated storage directory
     * @param candidateName Untrusted filename
     * @return Validated, normalized Path guaranteed to reside strictly within baseDirectory
     * @throws SecurityException If directory traversal or escape is detected
     */
    public static Path resolveSafePath(Path baseDirectory, String candidateName) {
        if (baseDirectory == null) {
            throw new IllegalArgumentException("Base directory cannot be null");
        }

        String safeName = sanitizeFilename(candidateName);
        Path normalizedBase = baseDirectory.toAbsolutePath().normalize();
        Path resolved = normalizedBase.resolve(safeName).normalize();

        assertSafePath(normalizedBase, resolved);
        return resolved;
    }

    /**
     * Asserts that a target path resides strictly within the boundary of a base directory.
     *
     * @param baseDirectory Sandboxed parent directory
     * @param candidatePath Path to verify
     * @throws SecurityException If candidatePath escapes baseDirectory
     */
    public static void assertSafePath(Path baseDirectory, Path candidatePath) {
        Path normBase = baseDirectory.toAbsolutePath().normalize();
        Path normCandidate = candidatePath.toAbsolutePath().normalize();

        if (!normCandidate.startsWith(normBase)) {
            throw new SecurityException("Path traversal attack detected: target path '"
                    + normCandidate + "' escapes base directory '" + normBase + "'");
        }
    }
}
