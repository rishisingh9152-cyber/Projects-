package com.packetanalyzer;

import com.packetanalyzer.dpi.BlockingRules;
import com.packetanalyzer.extractor.HTTPHostExtractor;
import com.packetanalyzer.extractor.SNIExtractor;
import com.packetanalyzer.model.*;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.reader.PcapReader;
import com.packetanalyzer.reader.PcapWriter;

import java.io.IOException;
import java.util.*;

/**
 * DPI Engine – Deep Packet Inspection System (Java port of main_working.cpp).
 *
 * <p>Usage:
 * <pre>
 *   java -jar PacketAnalyzer.jar &lt;input.pcap&gt; &lt;output.pcap&gt; [options]
 *
 *   Options:
 *     --block-ip     &lt;ip&gt;      Block traffic from source IP
 *     --block-app    &lt;app&gt;     Block application (YouTube, Facebook, …)
 *     --block-domain &lt;domain&gt;  Block domain (substring match)
 * </pre>
 */
public class DPIEngine {

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String inputFile  = args[0];
        String outputFile = args[1];

        // ── Parse command-line options ─────────────────────────────────────────
        BlockingRules rules = new BlockingRules();
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip"     -> { if (i + 1 < args.length) rules.blockIp(args[++i]); }
                case "--block-app"    -> { if (i + 1 < args.length) rules.blockApp(args[++i]); }
                case "--block-domain" -> { if (i + 1 < args.length) rules.blockDomain(args[++i]); }
                default -> System.err.println("[Warn] Unknown option: " + args[i]);
            }
        }

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0 (Java)                    ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();

        // ── Open input + output ────────────────────────────────────────────────
        PcapReader reader = new PcapReader();
        reader.open(inputFile);

        PcapWriter writer = new PcapWriter(outputFile, reader);

        // ── State ──────────────────────────────────────────────────────────────
        Map<FiveTuple, Flow>     flows    = new HashMap<>();
        Map<AppType, Long>       appStats = new EnumMap<>(AppType.class);

        long totalPackets = 0;
        long forwarded    = 0;
        long dropped      = 0;

        RawPacket    raw    = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();

        System.out.println("[DPI] Processing packets…");

        // ── Main packet loop ───────────────────────────────────────────────────
        while (reader.readNextPacket(raw)) {
            totalPackets++;

            if (!PacketParser.parse(raw, parsed)) continue;
            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

            // Build five-tuple
            FiveTuple tuple = new FiveTuple(
                FiveTuple.parseIp(parsed.srcIp),
                FiveTuple.parseIp(parsed.destIp),
                parsed.srcPort,
                parsed.destPort,
                parsed.protocol
            );

            // Get or create flow entry
            Flow flow = flows.computeIfAbsent(tuple, t -> { Flow f = new Flow(); f.tuple = t; return f; });
            flow.packets++;
            flow.bytes += raw.data.length;

            byte[] data          = raw.data;
            int    payloadOffset = parsed.payloadOffset;
            int    payloadLen    = parsed.payloadLength;

            // ── TLS / HTTPS SNI extraction ─────────────────────────────────────
            if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS) &&
                flow.sni.isEmpty() && parsed.hasTcp && parsed.destPort == 443) {

                if (payloadLen > 5) {
                    SNIExtractor.extract(data, payloadOffset, payloadLen).ifPresent(sni -> {
                        flow.sni     = sni;
                        flow.appType = AppType.fromSni(sni);
                    });
                }
            }

            // ── HTTP Host extraction ───────────────────────────────────────────
            if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTP) &&
                flow.sni.isEmpty() && parsed.hasTcp && parsed.destPort == 80) {

                if (payloadLen > 0) {
                    HTTPHostExtractor.extract(data, payloadOffset, payloadLen).ifPresent(host -> {
                        flow.sni     = host;
                        flow.appType = AppType.fromSni(host);
                    });
                }
            }

            // ── DNS classification ─────────────────────────────────────────────
            if (flow.appType == AppType.UNKNOWN &&
                (parsed.destPort == 53 || parsed.srcPort == 53)) {
                flow.appType = AppType.DNS;
            }

            // ── Port-based fallback ────────────────────────────────────────────
            if (flow.appType == AppType.UNKNOWN) {
                if      (parsed.destPort == 443) flow.appType = AppType.HTTPS;
                else if (parsed.destPort == 80)  flow.appType = AppType.HTTP;
            }

            // ── Apply blocking rules ───────────────────────────────────────────
            if (!flow.blocked) {
                flow.blocked = rules.isBlocked(tuple.srcIp, flow.appType, flow.sni);
                if (flow.blocked) {
                    System.out.print("[BLOCKED] " + parsed.srcIp + " -> " + parsed.destIp +
                                     " (" + flow.appType);
                    if (!flow.sni.isEmpty()) System.out.print(": " + flow.sni);
                    System.out.println(")");
                }
            }

            // ── Update app statistics ──────────────────────────────────────────
            appStats.merge(flow.appType, 1L, Long::sum);

            // ── Forward or drop ────────────────────────────────────────────────
            if (flow.blocked) {
                dropped++;
            } else {
                forwarded++;
                writer.writePacket(raw);
            }
        }

        reader.close();
        writer.close();

        // ── Print summary report ───────────────────────────────────────────────
        printReport(totalPackets, forwarded, dropped, flows, appStats, outputFile);
    }

    // ── Report ─────────────────────────────────────────────────────────────────

    private static void printReport(long total, long forwarded, long dropped,
                                    Map<FiveTuple, Flow> flows,
                                    Map<AppType, Long> appStats,
                                    String outputFile) {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                       ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf ("║ Total Packets:      %10d                             ║%n", total);
        System.out.printf ("║ Forwarded:          %10d                             ║%n", forwarded);
        System.out.printf ("║ Dropped:            %10d                             ║%n", dropped);
        System.out.printf ("║ Active Flows:       %10d                             ║%n", flows.size());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                    APPLICATION BREAKDOWN                     ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        // Sort by packet count descending
        List<Map.Entry<AppType, Long>> sorted = new ArrayList<>(appStats.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> e : sorted) {
            double pct    = total > 0 ? 100.0 * e.getValue() / total : 0.0;
            int    barLen = (int) (pct / 5);
            String bar    = "#".repeat(Math.max(0, barLen));
            System.out.printf("║ %-15s %8d %5.1f%% %-20s  ║%n",
                e.getKey().toString(), e.getValue(), pct, bar);
        }

        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        // Unique detected SNIs
        System.out.println("\n[Detected Applications/Domains]");
        Map<String, AppType> uniqueSnis = new LinkedHashMap<>();
        for (Flow flow : flows.values()) {
            if (!flow.sni.isEmpty()) uniqueSnis.put(flow.sni, flow.appType);
        }
        for (Map.Entry<String, AppType> e : uniqueSnis.entrySet()) {
            System.out.println("  - " + e.getKey() + " -> " + e.getValue());
        }

        System.out.println("\nOutput written to: " + outputFile);
    }

    // ── Usage ──────────────────────────────────────────────────────────────────

    private static void printUsage() {
        System.out.println("""

DPI Engine - Deep Packet Inspection System (Java)
=================================================

Usage: java -jar PacketAnalyzer.jar <input.pcap> <output.pcap> [options]

Options:
  --block-ip     <ip>      Block traffic from source IP
  --block-app    <app>     Block application (YouTube, Facebook, etc.)
  --block-domain <domain>  Block domain (substring match)

Example:
  java -jar PacketAnalyzer.jar capture.pcap filtered.pcap \\
       --block-app YouTube --block-ip 192.168.1.50
""");
    }
}
