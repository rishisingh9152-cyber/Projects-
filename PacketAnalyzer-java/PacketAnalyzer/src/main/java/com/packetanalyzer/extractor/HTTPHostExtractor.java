package com.packetanalyzer.extractor;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the {@code Host} header value from an HTTP/1.x request payload.
 */
public class HTTPHostExtractor {

    private static final byte[][] HTTP_METHODS = {
        "GET ".getBytes(StandardCharsets.US_ASCII),
        "POST".getBytes(StandardCharsets.US_ASCII),
        "PUT ".getBytes(StandardCharsets.US_ASCII),
        "HEAD".getBytes(StandardCharsets.US_ASCII),
        "DELE".getBytes(StandardCharsets.US_ASCII),
        "PATC".getBytes(StandardCharsets.US_ASCII),
        "OPTI".getBytes(StandardCharsets.US_ASCII)
    };

    public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
        if (length < 4) return false;
        for (byte[] method : HTTP_METHODS) {
            if (startsWith(payload, offset, length, method)) return true;
        }
        return false;
    }

    /**
     * Extracts the Host header value (port stripped if present).
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isHTTPRequest(payload, offset, length)) return Optional.empty();

        int end = offset + length;
        for (int i = offset; i + 5 < end; i++) {
            // Case-insensitive "Host:"
            if (toLower(payload[i])     == 'h' &&
                toLower(payload[i + 1]) == 'o' &&
                toLower(payload[i + 2]) == 's' &&
                toLower(payload[i + 3]) == 't' &&
                payload[i + 4] == ':') {

                // Skip "Host:" and any leading whitespace
                int start = i + 5;
                while (start < end && (payload[start] == ' ' || payload[start] == '\t')) start++;

                // Find end of header line
                int lineEnd = start;
                while (lineEnd < end && payload[lineEnd] != '\r' && payload[lineEnd] != '\n') lineEnd++;

                if (lineEnd > start) {
                    String host = new String(payload, start, lineEnd - start, StandardCharsets.US_ASCII);
                    // Strip port if present
                    int colon = host.indexOf(':');
                    if (colon != -1) host = host.substring(0, colon);
                    return Optional.of(host.trim());
                }
            }
        }
        return Optional.empty();
    }

    /** Convenience overload starting at index 0. */
    public static Optional<String> extract(byte[] payload, int length) {
        return extract(payload, 0, length);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static char toLower(byte b) { return (char) Character.toLowerCase(b & 0xFF); }

    private static boolean startsWith(byte[] data, int offset, int len, byte[] prefix) {
        if (len < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (data[offset + i] != prefix[i]) return false;
        }
        return true;
    }
}
