package com.packetanalyzer.reader;

import com.packetanalyzer.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Writes packets to a PCAP file (little-endian / native format).
 */
public class PcapWriter implements Closeable {

    private final OutputStream out;

    public PcapWriter(String filename, PcapReader sourceHeader) throws IOException {
        out = new BufferedOutputStream(new FileOutputStream(filename));
        sourceHeader.writeGlobalHeader(out);
    }

    /** Writes a single raw packet (packet header + data). */
    public void writePacket(RawPacket pkt) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) pkt.tsSec);
        buf.putInt((int) pkt.tsUsec);
        buf.putInt(pkt.data.length);
        buf.putInt(pkt.data.length);
        out.write(buf.array());
        out.write(pkt.data);
    }

    @Override
    public void close() throws IOException {
        out.close();
    }
}
