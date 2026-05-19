package com.packetanalyzer.model;

import java.util.Objects;

/**
 * Uniquely identifies a network connection/flow using 5 fields.
 */
public class FiveTuple {
    public final long srcIp;   // stored as unsigned 32-bit in a long
    public final long dstIp;
    public final int srcPort;
    public final int dstPort;
    public final int protocol;  // TCP=6, UDP=17

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    /** Returns the reverse tuple (for matching bidirectional flows). */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    public static long parseIp(String ip) {
        long result = 0;
        int shift = 0;
        for (String part : ip.split("\\.")) {
            result |= (long) Integer.parseInt(part) << shift;
            shift += 8;
        }
        return result;
    }

    public static String ipToString(long ip) {
        return (ip & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 24) & 0xFF);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcIp == t.srcIp && dstIp == t.dstIp &&
               srcPort == t.srcPort && dstPort == t.dstPort && protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        String proto = protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?";
        return ipToString(srcIp) + ":" + srcPort + " -> " + ipToString(dstIp) + ":" + dstPort + " (" + proto + ")";
    }
}
