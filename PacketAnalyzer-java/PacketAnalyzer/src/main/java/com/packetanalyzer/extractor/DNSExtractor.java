package com.packetanalyzer.extractor;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the queried domain name from a DNS query payload.
 */
public class DNSExtractor {

    /** Returns true if the payload looks like a DNS query (not a response). */
    public static boolean isDNSQuery(byte[] payload, int offset, int length) {
        if (length < 12) return false;
        // QR bit (byte 2, bit 7) must be 0 for a query
        if ((payload[offset + 2] & 0x80) != 0) return false;
        // QDCOUNT (bytes 4-5) must be > 0
        int qdcount = ((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF);
        return qdcount > 0;
    }

    /** Extracts the first queried domain name from a DNS query. */
    public static Optional<String> extractQuery(byte[] payload, int offset, int length) {
        if (!isDNSQuery(payload, offset, length)) return Optional.empty();

        int pos = offset + 12; // DNS question section starts after the 12-byte header
        StringBuilder domain = new StringBuilder();
        int end = offset + length;

        while (pos < end) {
            int labelLen = payload[pos] & 0xFF;
            if (labelLen == 0) break;          // end of name
            if (labelLen > 63) break;          // compression pointer – skip

            pos++;
            if (pos + labelLen > end) break;

            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, pos, labelLen, StandardCharsets.US_ASCII));
            pos += labelLen;
        }

        return domain.length() > 0 ? Optional.of(domain.toString()) : Optional.empty();
    }

    /** Convenience overload starting at index 0. */
    public static Optional<String> extractQuery(byte[] payload, int length) {
        return extractQuery(payload, 0, length);
    }
}
