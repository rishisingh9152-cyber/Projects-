package com.packetanalyzer.parser;

import com.packetanalyzer.model.ParsedPacket;
import com.packetanalyzer.model.RawPacket;

/**
 * Parses raw packet bytes into a human-readable {@link ParsedPacket}.
 * Supports Ethernet → IPv4 → TCP/UDP.
 */
public class PacketParser {

    // EtherType constants
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP  = 0x0806;

    // IP protocol numbers
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    // TCP flag bitmasks
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    /**
     * Parses a raw packet.
     *
     * @return true if at least the Ethernet header was successfully parsed
     */
    public static boolean parse(RawPacket raw, ParsedPacket out) {
        out.data = raw.data;
        out.timestampSec  = raw.tsSec;
        out.timestampUsec = raw.tsUsec;

        byte[] d = raw.data;
        int len = d.length;
        int offset = 0;

        // ── Ethernet (14 bytes) ────────────────────────────────────────────
        if (len < 14) return false;

        out.destMac = macToString(d, 0);
        out.srcMac  = macToString(d, 6);
        out.etherType = u16(d, 12);
        offset = 14;

        if (out.etherType != ETHERTYPE_IPV4) return true; // non-IPv4 – stop here

        // ── IPv4 ──────────────────────────────────────────────────────────
        if (len < offset + 20) return false;

        int versionIhl = u8(d, offset);
        out.ipVersion  = (versionIhl >> 4) & 0x0F;
        if (out.ipVersion != 4) return false;

        int ihl = (versionIhl & 0x0F) * 4;
        if (ihl < 20 || len < offset + ihl) return false;

        out.ttl      = u8(d, offset + 8);
        out.protocol = u8(d, offset + 9);
        out.srcIp    = ipToString(d, offset + 12);
        out.destIp   = ipToString(d, offset + 16);
        out.hasIp    = true;
        offset += ihl;

        // ── TCP ───────────────────────────────────────────────────────────
        if (out.protocol == PROTO_TCP) {
            if (len < offset + 20) return false;

            out.srcPort   = u16(d, offset);
            out.destPort  = u16(d, offset + 2);
            out.seqNumber = u32(d, offset + 4);
            out.ackNumber = u32(d, offset + 8);
            int dataOffset = ((u8(d, offset + 12) >> 4) & 0x0F) * 4;
            out.tcpFlags  = u8(d, offset + 13);
            if (dataOffset < 20 || len < offset + dataOffset) return false;
            out.hasTcp = true;
            offset += dataOffset;

        // ── UDP ───────────────────────────────────────────────────────────
        } else if (out.protocol == PROTO_UDP) {
            if (len < offset + 8) return false;
            out.srcPort  = u16(d, offset);
            out.destPort = u16(d, offset + 2);
            out.hasUdp   = true;
            offset += 8;
        }

        out.payloadOffset = offset;
        out.payloadLength = Math.max(0, len - offset);
        return true;
    }

    // ── Formatting helpers ────────────────────────────────────────────────────

    public static String macToString(byte[] data, int offset) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
            data[offset] & 0xFF, data[offset+1] & 0xFF, data[offset+2] & 0xFF,
            data[offset+3] & 0xFF, data[offset+4] & 0xFF, data[offset+5] & 0xFF);
    }

    public static String ipToString(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "." + (data[offset+1] & 0xFF) + "." +
               (data[offset+2] & 0xFF) + "." + (data[offset+3] & 0xFF);
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case PROTO_ICMP -> "ICMP";
            case PROTO_TCP  -> "TCP";
            case PROTO_UDP  -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_SYN) != 0) sb.append("SYN ");
        if ((flags & TCP_ACK) != 0) sb.append("ACK ");
        if ((flags & TCP_FIN) != 0) sb.append("FIN ");
        if ((flags & TCP_RST) != 0) sb.append("RST ");
        if ((flags & TCP_PSH) != 0) sb.append("PSH ");
        if ((flags & TCP_URG) != 0) sb.append("URG ");
        String s = sb.toString().trim();
        return s.isEmpty() ? "none" : s;
    }

    // ── Byte-reading utilities (big-endian network order) ─────────────────────

    private static int u8(byte[] d, int i)  { return d[i] & 0xFF; }
    private static int u16(byte[] d, int i) { return ((d[i] & 0xFF) << 8) | (d[i+1] & 0xFF); }
    private static long u32(byte[] d, int i) {
        return ((long)(d[i] & 0xFF) << 24) | ((d[i+1] & 0xFF) << 16) |
               ((d[i+2] & 0xFF) << 8)  |  (d[i+3] & 0xFF);
    }
}
