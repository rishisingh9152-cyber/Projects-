# PacketAnalyzer-java

A high-performance Deep Packet Inspection (DPI) engine written in Java that analyzes, classifies, and filters network traffic from PCAP (Packet Capture) files.

## Overview

PacketAnalyzer-java is a Java port of a C++ DPI system designed to:

- **Read and parse** network packets from PCAP files
- **Classify** traffic by application type (HTTP, HTTPS, DNS, TLS, QUIC, etc.)
- **Extract** application identifiers (SNI, Host headers, DNS queries)
- **Filter** packets based on custom rules (IP, application, domain)
- **Generate** detailed analysis reports with statistics
- **Write** filtered packets to output PCAP files

Perfect for network security, traffic analysis, content filtering, and network monitoring applications.

## Features

- ✅ **Zero External Dependencies** - Pure Java implementation
- ✅ **Efficient Flow Tracking** - O(1) flow state lookup and management
- ✅ **Protocol Support** - Ethernet, IPv4, TCP, UDP, TLS, HTTP, DNS
- ✅ **Intelligent Application Classification** - Domain-based matching for popular services
- ✅ **Flexible Filtering** - Block by IP, application type, or domain pattern
- ✅ **Comprehensive Reporting** - Detailed statistics with application breakdown
- ✅ **Memory Efficient** - Streams packets rather than loading all in memory
- ✅ **Automatic Byte Order Detection** - Handles both little-endian and big-endian PCAP files

## Quick Start

### Prerequisites

- Java 17 or later
- Maven 3.6.0 or later (for building from source)

### Building

```bash
cd PacketAnalyzer
mvn clean package
```

This generates `target/PacketAnalyzer.jar` - a single executable fat JAR with all dependencies.

### Running

```bash
java -jar PacketAnalyzer.jar <input.pcap> <output.pcap> [options]
```

### Basic Example

Analyze a PCAP file and save filtered output:

```bash
java -jar PacketAnalyzer.jar capture.pcap filtered.pcap
```

### With Filtering Rules

Block specific applications and IPs:

```bash
java -jar PacketAnalyzer.jar capture.pcap filtered.pcap \
  --block-app YouTube \
  --block-app Facebook \
  --block-ip 192.168.1.50
```

### Available Blocking Options

```
--block-ip <ip>         Block traffic from source IP address
--block-app <app>       Block application type or service
                        Supported: HTTP, HTTPS, DNS, TLS, QUIC,
                        Google, Facebook, YouTube, Twitter, Instagram,
                        Netflix, Amazon, Microsoft, Apple, WhatsApp,
                        Telegram, TikTok, Spotify, Zoom, Discord,
                        GitHub, Cloudflare

--block-domain <domain> Block domain (substring pattern matching)
```

## Project Structure

```
PacketAnalyzer-java/
├── README.md
├── PacketAnalyzer/
│   ├── pom.xml                              # Maven configuration
│   └── src/main/java/com/packetanalyzer/
│       ├── DPIEngine.java                   # Main orchestrator
│       ├── model/                           # Data models
│       │   ├── AppType.java                 # Application type enum
│       │   ├── Flow.java                    # Network flow tracking
│       │   ├── FiveTuple.java               # Flow identifier
│       │   ├── ParsedPacket.java            # Parsed packet data
│       │   └── RawPacket.java               # Raw packet bytes
│       ├── parser/
│       │   └── PacketParser.java            # Packet layer parsing
│       ├── reader/
│       │   ├── PcapReader.java              # PCAP file reader
│       │   └── PcapWriter.java              # PCAP file writer
│       ├── extractor/
│       │   ├── SNIExtractor.java            # TLS SNI extraction
│       │   ├── HTTPHostExtractor.java       # HTTP Host extraction
│       │   └── DNSExtractor.java            # DNS query extraction
│       └── dpi/
│           └── BlockingRules.java           # Filtering rules engine
```

## How It Works

### Processing Pipeline

1. **Parse Arguments** → Initialize blocking rules from command-line options
2. **Open Files** → Load input PCAP and prepare output PCAP
3. **Process Packets** → For each packet:
   - Parse raw bytes into structured packet format
   - Skip non-IP and non-TCP/UDP traffic
   - Build/retrieve network flow from packet 5-tuple
   - Extract application identifiers:
     - TLS SNI (port 443)
     - HTTP Host header (port 80)
     - DNS queries (port 53)
   - Classify application using extracted identifiers
   - Evaluate blocking rules
   - Forward or drop packet to output file
   - Update statistics
4. **Generate Report** → Display analysis and statistics

### Network Flow Tracking

The engine maintains a bidirectional flow map to track:
- Source/destination IP addresses
- Port numbers
- Protocol (TCP/UDP)
- Application type
- Domain/SNI information
- Packet and byte counts
- Blocked status

This enables efficient state tracking and duplicate detection.

## Components

### DPIEngine
Main orchestrator that coordinates the entire pipeline. Manages flow state, collects statistics, and generates reports.

**Key Methods:**
- `main()` - Entry point and command-line argument parsing
- `processPackets()` - Main packet processing loop
- `generateReport()` - Statistics and analysis reporting

### Model Classes

**AppType** - Enum of supported applications
- Protocol types: HTTP, HTTPS, DNS, TLS, QUIC
- Popular services: Google, Facebook, YouTube, Netflix, etc.
- Domain-based classification via `fromSni()` method

**FiveTuple** - Flow identifier (source IP, destination IP, source port, destination port, protocol)
- Immutable with proper `hashCode()` and `equals()`
- Includes reverse tuple support for bidirectional matching
- IP address parsing and formatting utilities

**Flow** - Network connection tracking
- Contains: 5-tuple, application type, SNI, statistics
- Tracks packets, bytes, and blocked status

**ParsedPacket** - Structured packet representation
- Headers: MAC, IP, TCP/UDP
- Payload information
- Timestamps and metadata

### Packet Parser

**PacketParser** - Layer 2-4 protocol parsing
- Ethernet frame parsing
- IPv4 header parsing (with variable IHL support)
- TCP header parsing (flags, sequence numbers, ACK)
- UDP header parsing
- Payload offset/length calculation

Supports variable-length headers and handles edge cases gracefully.

### PCAP I/O

**PcapReader**
- Auto-detects byte order (little-endian vs big-endian)
- Validates PCAP magic numbers
- Reads global and packet headers
- Streams packets efficiently

**PcapWriter**
- Writes filtered packets to output PCAP
- Preserves packet headers and timestamps
- Maintains compatibility with standard PCAP format

### Protocol Extractors

**SNIExtractor** - TLS Server Name Indication extraction
- Parses TLS Client Hello records (RFC 5246/8446)
- Extracts hostname from SNI extension
- Returns `Optional<String>` for safe handling

**HTTPHostExtractor** - HTTP Host header extraction
- Detects HTTP methods and requests
- Case-insensitive header parsing
- Strips port numbers
- Returns `Optional<String>`

**DNSExtractor** - DNS query extraction
- Distinguishes DNS queries from responses
- Parses DNS question section
- Handles DNS label encoding
- Returns `Optional<String>`

### BlockingRules

Flexible rule engine supporting:
- **IP-based blocking** - Block by source IP address
- **Application-based blocking** - Block by AppType
- **Domain-based blocking** - Substring pattern matching

**Methods:**
- `blockIp(String ip)` - Add IP block rule
- `blockApp(AppType app)` - Add application block rule
- `blockDomain(String domain)` - Add domain block rule
- `isBlocked(ParsedPacket, AppType, String sni)` - Check if packet should be dropped

## Output Report

The engine generates a comprehensive report including:

```
╔════════════════════════════════════════╗
║   PacketAnalyzer - DPI Report          ║
╚════════════════════════════════════════╝

Total Packets Processed:    12,345
Packets Forwarded:           9,876
Packets Dropped:             2,469
Active Flows:                  234

Application Breakdown:
  ┌─────────────────────┬───────┬────────┐
  │ Application         │ Count │ % Total│
  ├─────────────────────┼───────┼────────┤
  │ HTTPS              │  8,234│ 66.7%  │
  │ HTTP               │  2,145│ 17.4%  │
  │ DNS                │  1,423│ 11.5%  │
  │ TLS                │    543│  4.4%  │
  └─────────────────────┴───────┴────────┘

Output PCAP: filtered.pcap
```

## Technical Specifications

- **Language**: Java 17
- **Build Tool**: Maven 3.6.0+
- **Packaging**: Fat JAR (single executable file)
- **Dependencies**: None (zero external dependencies)
- **Memory Model**: Streaming architecture with HashMap-based flow tracking
- **Performance**: O(1) packet processing with flow state lookup

## Supported Protocols

### Layer 2 (Data Link)
- Ethernet II

### Layer 3 (Network)
- IPv4

### Layer 4 (Transport)
- TCP
- UDP

### Layer 7 (Application)
- **TLS/SSL** - SNI extraction from Client Hello
- **HTTP/1.x** - Host header extraction
- **DNS** - Query domain extraction
- **HTTPS/QUIC** - Application classification

## Design Patterns

- **Optional Pattern** - Used for safe optional extractions
- **Enum-based Classification** - Type-safe application types
- **HashMap Flow Tracking** - O(1) state lookup
- **Immutable Records** - Immutable FiveTuple for thread-safety
- **Resource Management** - Closeable implementations
- **Bit Manipulation** - Low-level protocol parsing

## Performance Characteristics

- **Packet Processing**: O(1) with HashMap-based flow lookup
- **Memory**: Proportional to active flow count, not packet count
- **Throughput**: Streams packets, suitable for large PCAP files
- **Latency**: Minimal processing overhead per packet

## Error Handling

- Graceful EOF handling for incomplete PCAP files
- Tolerates invalid packets without crashing
- Optional-based extraction for optional protocol fields
- Comprehensive input validation

## Building from Source

```bash
# Clone or download the repository
cd PacketAnalyzer-java/PacketAnalyzer

# Build with Maven
mvn clean package

# Run tests (if any)
mvn test

# The JAR will be at target/PacketAnalyzer.jar
```

## Usage Examples

### Example 1: Basic Analysis
```bash
java -jar PacketAnalyzer.jar network_capture.pcap analysis_output.pcap
```

### Example 2: Block Specific Services
```bash
java -jar PacketAnalyzer.jar traffic.pcap filtered.pcap \
  --block-app YouTube \
  --block-app TikTok \
  --block-app Netflix
```

### Example 3: Block by IP Address
```bash
java -jar PacketAnalyzer.jar traffic.pcap filtered.pcap \
  --block-ip 192.168.1.100 \
  --block-ip 10.0.0.50
```

### Example 4: Comprehensive Filtering
```bash
java -jar PacketAnalyzer.jar capture.pcap safe_output.pcap \
  --block-app Facebook \
  --block-app Instagram \
  --block-ip 203.0.113.45 \
  --block-domain "ads.example.com"
```

## Troubleshooting

### "Invalid PCAP file" error
- Ensure input file is a valid PCAP format
- Check file is not corrupted
- Verify byte order (little-endian vs big-endian)

### "Out of Memory" error
- Process smaller PCAP files in chunks
- Increase JVM heap: `java -Xmx2G -jar PacketAnalyzer.jar ...`

### No applications detected
- Verify PCAP contains HTTP/TLS traffic with SNI or Host headers
- Check that packets are not truncated (snaplen too small)

## Future Enhancements

Potential improvements for future versions:
- IPv6 support
- Additional protocol support (RTMP, SSH, etc.)
- Machine learning-based classification
- Real-time traffic analysis from network interface
- Performance optimization for multi-core systems
- GUI dashboard for live monitoring

## License

Specify your project license here.

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch
3. Ensure code follows Java conventions
4. Add tests for new functionality
5. Submit a pull request

## Support

For issues, questions, or suggestions:
- Open an issue on the project repository
- Check existing documentation
- Review example usage cases

---

**PacketAnalyzer-java** - Professional-grade network traffic analysis for Java applications.
