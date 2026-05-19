package com.packetanalyzer.model;

/**
 * Represents a single raw captured packet read from a PCAP file.
 */
public class RawPacket {
    // From PCAP packet header (16 bytes)
    public long tsSec;    // Timestamp seconds
    public long tsUsec;   // Timestamp microseconds
    public long inclLen;  // Bytes saved in file
    public long origLen;  // Actual packet length

    // Raw packet data
    public byte[] data;
}
