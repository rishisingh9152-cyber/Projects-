package com.packetanalyzer.extractor;

import java.util.Optional;

/**
 * Extracts the Server Name Indication (SNI) from a TLS Client Hello record.
 *
 * <p>TLS record format (RFC 5246 / RFC 8446):
 * <pre>
 *  Byte 0     : Content Type (0x16 = Handshake)
 *  Bytes 1-2  : TLS version
 *  Bytes 3-4  : Record length
 *  Byte 5     : Handshake type (0x01 = Client Hello)
 *  Bytes 6-8  : Handshake length (24-bit big-endian)
 *  …          : Client Hello body
 * </pre>
 */
public class SNIExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE  = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO  = 0x01;
    private static final int EXTENSION_SNI           = 0x0000;
    private static final int SNI_TYPE_HOSTNAME       = 0x00;

    /**
     * Attempts to extract the SNI hostname from raw TLS payload bytes.
     *
     * @param payload byte array starting at the TLS record
     * @param offset  start offset within the array
     * @param length  number of bytes available
     * @return the hostname, or {@link Optional#empty()} if not found
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isTLSClientHello(payload, offset, length)) return Optional.empty();

        int pos = offset + 5; // skip TLS record header

        // Skip handshake header (type already checked + 3-byte length)
        pos += 4;

        // Client version (2 bytes)
        pos += 2;

        // Random (32 bytes)
        pos += 32;

        // Session ID
        if (pos >= offset + length) return Optional.empty();
        int sessionIdLen = u8(payload, pos++);
        pos += sessionIdLen;

        // Cipher suites
        if (pos + 2 > offset + length) return Optional.empty();
        int cipherLen = u16(payload, pos);
        pos += 2 + cipherLen;

        // Compression methods
        if (pos >= offset + length) return Optional.empty();
        int comprLen = u8(payload, pos++);
        pos += comprLen;

        // Extensions
        if (pos + 2 > offset + length) return Optional.empty();
        int extTotalLen = u16(payload, pos);
        pos += 2;
        int extEnd = Math.min(pos + extTotalLen, offset + length);

        while (pos + 4 <= extEnd) {
            int extType = u16(payload, pos);
            int extLen  = u16(payload, pos + 2);
            pos += 4;

            if (pos + extLen > extEnd) break;

            if (extType == EXTENSION_SNI) {
                // SNI List Length (2) + SNI Type (1) + SNI Length (2) + value
                if (extLen < 5) break;
                // skip list-length field
                int sniType = u8(payload, pos + 2);
                int sniLen  = u16(payload, pos + 3);
                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLen > extLen - 5) break;
                return Optional.of(new String(payload, pos + 5, sniLen));
            }

            pos += extLen;
        }

        return Optional.empty();
    }

    /** Convenience overload taking a plain byte[] starting at index 0. */
    public static Optional<String> extract(byte[] payload, int length) {
        return extract(payload, 0, length);
    }

    // ── TLS Client Hello detection ────────────────────────────────────────────

    private static boolean isTLSClientHello(byte[] d, int off, int len) {
        if (len < 9) return false;
        if (u8(d, off) != CONTENT_TYPE_HANDSHAKE) return false;
        int version = u16(d, off + 1);
        if (version < 0x0300 || version > 0x0304) return false;
        int recordLen = u16(d, off + 3);
        if (recordLen > len - 5) return false;
        return u8(d, off + 5) == HANDSHAKE_CLIENT_HELLO;
    }

    // ── Byte helpers (network / big-endian) ───────────────────────────────────

    private static int u8(byte[] d, int i)  { return d[i] & 0xFF; }
    private static int u16(byte[] d, int i) { return ((d[i] & 0xFF) << 8) | (d[i+1] & 0xFF); }
}
