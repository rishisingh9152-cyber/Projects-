package com.packetanalyzer.reader;

import com.packetanalyzer.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads packets from a PCAP file.
 * Handles both native and byte-swapped (big-endian) PCAP files.
 */
public class PcapReader implements Closeable {

    private static final long PCAP_MAGIC_NATIVE  = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    private DataInputStream in;
    private boolean needsByteSwap;

    // Global header fields
    private int versionMajor;
    private int versionMinor;
    private long snaplen;
    private long network;

    /**
     * Opens a PCAP file and reads its global header.
     *
     * @param filename path to the .pcap file
     * @throws IOException if the file cannot be opened or is not a valid PCAP
     */
    public void open(String filename) throws IOException {
        in = new DataInputStream(new BufferedInputStream(new FileInputStream(filename)));

        // Read and inspect the 4-byte magic number
        long magic = readUint32Raw();
        if (magic == PCAP_MAGIC_NATIVE) {
            needsByteSwap = false;
        } else if (magic == PCAP_MAGIC_SWAPPED) {
            needsByteSwap = true;
        } else {
            throw new IOException(String.format("Invalid PCAP magic number: 0x%08X", magic));
        }

        // Read rest of 24-byte global header
        versionMajor = readUint16();
        versionMinor = readUint16();
        readInt32();   // thiszone (ignored)
        readUint32();  // sigfigs  (ignored)
        snaplen  = readUint32();
        network  = readUint32();

        System.out.println("Opened PCAP file: " + filename);
        System.out.printf("  Version: %d.%d%n", versionMajor, versionMinor);
        System.out.printf("  Snaplen: %d bytes%n", snaplen);
        System.out.printf("  Link type: %d%s%n", network, network == 1 ? " (Ethernet)" : "");
    }

    /**
     * Reads the next packet from the file.
     *
     * @param packet output object to fill
     * @return true if a packet was read, false at end-of-file
     * @throws IOException on read errors
     */
    public boolean readNextPacket(RawPacket packet) throws IOException {
        // Try reading the 16-byte packet header
        byte[] hdrBuf = new byte[16];
        int read = 0;
        while (read < 16) {
            int n = in.read(hdrBuf, read, 16 - read);
            if (n == -1) return false;   // EOF
            read += n;
        }

        ByteBuffer hdr = ByteBuffer.wrap(hdrBuf)
                .order(needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

        packet.tsSec   = Integer.toUnsignedLong(hdr.getInt());
        packet.tsUsec  = Integer.toUnsignedLong(hdr.getInt());
        packet.inclLen = Integer.toUnsignedLong(hdr.getInt());
        packet.origLen = Integer.toUnsignedLong(hdr.getInt());

        if (packet.inclLen > snaplen || packet.inclLen > 65535) {
            throw new IOException("Invalid packet length: " + packet.inclLen);
        }

        packet.data = new byte[(int) packet.inclLen];
        in.readFully(packet.data);
        return true;
    }

    // -------------------------------------------------------------------------
    // Getters for global header fields
    // -------------------------------------------------------------------------
    public int getVersionMajor() { return versionMajor; }
    public int getVersionMinor() { return versionMinor; }
    public long getSnaplen()     { return snaplen; }
    public long getNetwork()     { return network; }
    public boolean needsByteSwap() { return needsByteSwap; }

    /**
     * Writes the PCAP global header to the given stream (for output files).
     */
    public void writeGlobalHeader(OutputStream out) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) PCAP_MAGIC_NATIVE);
        buf.putShort((short) versionMajor);
        buf.putShort((short) versionMinor);
        buf.putInt(0);             // thiszone
        buf.putInt(0);             // sigfigs
        buf.putInt((int) snaplen);
        buf.putInt((int) network);
        out.write(buf.array());
    }

    @Override
    public void close() throws IOException {
        if (in != null) { in.close(); in = null; }
    }

    // -------------------------------------------------------------------------
    // Raw read helpers (little-endian native, big-endian if byte-swapped)
    // -------------------------------------------------------------------------
    private long readUint32Raw() throws IOException {
        byte[] b = in.readNBytes(4);
        return Integer.toUnsignedLong(
            ((b[0] & 0xFF)) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24));
    }

    private long readUint32() throws IOException {
        if (!needsByteSwap) return readUint32Raw();
        byte[] b = in.readNBytes(4);
        return Integer.toUnsignedLong(
            ((b[3] & 0xFF)) | ((b[2] & 0xFF) << 8) | ((b[1] & 0xFF) << 16) | ((b[0] & 0xFF) << 24));
    }

    private int readUint16() throws IOException {
        int lo = in.readUnsignedByte();
        int hi = in.readUnsignedByte();
        return needsByteSwap ? (lo << 8) | hi : lo | (hi << 8);
    }

    private int readInt32() throws IOException {
        return (int) readUint32();
    }
}
