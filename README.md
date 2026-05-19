# Projects Repository

A comprehensive collection of advanced software engineering projects showcasing modern development practices, innovative solutions, and best practices across multiple domains.

## Overview

This repository contains three independently functioning projects:

1. **Medical Chatbot** - AI-powered healthcare assistant using RAG (Retrieval-Augmented Generation)
2. **PacketAnalyzer** - High-performance network traffic analysis and Deep Packet Inspection (DPI)
3. **UPI Without Internet** - Offline payment system with mesh networking and hybrid encryption

---

## 📋 Project Index

### 1. Medical Chatbot (Python + LLM)

**Location:** `Medical-Chatbot-main/Medical-Chatbot-main/`

A retrieval-augmented generation (RAG) chatbot powered by LangChain, FAISS, and Groq's LLM for answering medical queries based on PDF documents.

#### Key Features
- 📄 **PDF Document Processing** - Automatically loads and processes PDF files
- 🔍 **Semantic Search** - Uses FAISS vector database for fast similarity search
- 🤖 **AI-Powered Responses** - Leverages Groq's LLaMA 3.1 8B model
- 💬 **Conversational Interface** - Interactive Streamlit web application with chat history
- 📚 **Context-Aware** - Retrieves relevant document chunks to ground responses
- ⚡ **Optimized Performance** - Caches vector store for faster inference

#### Tech Stack
- **Framework:** Streamlit (Web UI)
- **LLM:** Groq (LLaMA 3.1 8B)
- **Vector Database:** FAISS
- **Embeddings:** Sentence Transformers (HuggingFace)
- **Document Processing:** LangChain, PyPDF
- **Language:** Python 3.11+

#### Quick Start
```bash
cd Medical-Chatbot-main/Medical-Chatbot-main

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
echo "GROQ_API_KEY=your_key_here" > .env

# Create vector embeddings
python create_memory_for_llm.py

# Run the chatbot
streamlit run medibot.py
```

**Open:** http://localhost:8501

#### Project Structure
```
Medical-Chatbot-main/
├── medibot.py                      # Main Streamlit application
├── create_memory_for_llm.py        # Vector embedding creation
├── connect_memory_with_llm.py      # RAG chain testing
├── data/                           # PDF documents directory
├── vectorstore/db_faiss/           # FAISS vector database
└── requirements.txt                # Python dependencies
```

---

### 2. PacketAnalyzer (Java)

**Location:** `PacketAnalyzer-java/PacketAnalyzer/`

A high-performance Deep Packet Inspection (DPI) engine that analyzes, classifies, and filters network traffic from PCAP files.

#### Key Features
- ✅ **Zero External Dependencies** - Pure Java implementation
- ✅ **Efficient Flow Tracking** - O(1) flow state lookup
- ✅ **Protocol Support** - Ethernet, IPv4, TCP, UDP, TLS, HTTP, DNS
- ✅ **Intelligent Classification** - Domain-based matching for services
- ✅ **Flexible Filtering** - Block by IP, application type, or domain
- ✅ **Comprehensive Reporting** - Detailed statistics with breakdown
- ✅ **Memory Efficient** - Streams packets rather than loading all

#### Tech Stack
- **Language:** Java 17+
- **Build Tool:** Maven 3.6.0+
- **Architecture:** Single Fat JAR
- **Dependencies:** Zero external dependencies

#### Quick Start
```bash
cd PacketAnalyzer-java/PacketAnalyzer

# Build
mvn clean package

# Basic analysis
java -jar target/PacketAnalyzer.jar input.pcap output.pcap

# Block specific applications
java -jar target/PacketAnalyzer.jar capture.pcap filtered.pcap \
  --block-app YouTube \
  --block-app Netflix \
  --block-ip 192.168.1.50
```

#### Blocking Options
- `--block-ip <ip>` - Block by source IP address
- `--block-app <app>` - Block application type (HTTP, HTTPS, DNS, TLS, QUIC, YouTube, Netflix, Facebook, etc.)
- `--block-domain <domain>` - Block domain (substring pattern matching)

#### Project Structure
```
PacketAnalyzer-java/
├── README.md
└── PacketAnalyzer/
    ├── pom.xml
    └── src/main/java/com/packetanalyzer/
        ├── DPIEngine.java              # Main orchestrator
        ├── model/                      # Data models (Flow, ParsedPacket, etc.)
        ├── parser/                     # Packet layer parsing
        ├── reader/                     # PCAP file I/O
        ├── extractor/                  # Protocol extractors (SNI, HTTP, DNS)
        └── dpi/                        # Filtering rules engine
```

#### Processing Pipeline
1. Parse command-line arguments
2. Open input/output PCAP files
3. For each packet:
   - Parse raw bytes into structured format
   - Extract application identifiers (SNI, Host header, DNS query)
   - Classify application
   - Evaluate blocking rules
   - Forward or drop packet
   - Update statistics
4. Generate comprehensive report

---

### 3. UPI Without Internet (Java + Spring Boot)

**Location:** `UPI_Without_Internet-main/`

A Spring Boot backend demonstrating offline UPI payments routed through a Bluetooth-style mesh network. Features hybrid encryption, idempotency, and deduplication.

#### Key Features
- 🔐 **Hybrid Encryption** - RSA-OAEP + AES-256-GCM for untrusted intermediaries
- 🔄 **Idempotency** - Atomic deduplication ensures exactly-once settlement
- 🛡️ **Tamper Detection** - GCM authentication detects tampering
- ⏱️ **Replay Protection** - Nonce + timestamp prevents replays
- 📊 **Interactive Dashboard** - Web UI to simulate the full payment flow
- ⚙️ **Zero Setup** - No database/Redis needed (embedded H2)

#### Tech Stack
- **Framework:** Spring Boot 3.3.5
- **Language:** Java 17+
- **Database:** H2 (in-memory)
- **ORM:** Spring Data JPA
- **Web:** Embedded Tomcat
- **Cryptography:** RSA-OAEP, AES-256-GCM
- **UI:** Thymeleaf + JavaScript

#### Quick Start
```bash
cd UPI_Without_Internet-main

# Windows
mvnw.cmd spring-boot:run

# Mac/Linux
./mvnw spring-boot:run
```

**Open:** http://localhost:8080

The dashboard provides interactive buttons to:
1. **Inject into Mesh** - Create and encrypt a payment
2. **Run Gossip Round** - Simulate mesh network propagation
3. **Bridges Upload** - Simulate bridge nodes uploading to backend
4. **Reset Mesh** - Clear state and cache

#### The Three Hard Problems

**Problem 1: Untrusted Intermediates**
- Solution: Hybrid encryption (RSA-OAEP + AES-256-GCM)
- Sender encrypts with server's public key
- Only server can decrypt

**Problem 2: Duplicate Storm**
- Solution: Atomic compare-and-set on ciphertext hash
- `ConcurrentHashMap.putIfAbsent()` ensures exactly-once settlement
- Duplicates rejected before decryption

**Problem 3: Replay Attacks**
- Solution: Dual-layer protection
  1. Encrypted payload includes `signedAt` timestamp (24h freshness check)
  2. Encrypted payload includes unique `nonce` (UUID)

#### API Endpoints
| Method | Path | Description |
|---|---|---|
| GET | `/` | Dashboard |
| GET | `/api/server-key` | RSA public key (base64) |
| GET | `/api/accounts` | Account balances |
| GET | `/api/transactions` | Transaction ledger |
| GET | `/api/mesh/state` | Virtual device states |
| POST | `/api/demo/send` | Create + encrypt payment |
| POST | `/api/mesh/gossip` | Gossip round |
| POST | `/api/mesh/flush` | Bridge upload |
| POST | `/api/bridge/ingest` | **Production endpoint** |

#### Project Structure
```
UPI_Without_Internet-main/
├── pom.xml                              # Maven configuration
├── mvnw / mvnw.cmd                      # Maven wrapper
├── src/main/resources/
│   ├── application.properties           # Configuration
│   └── templates/dashboard.html         # Demo UI
└── src/main/java/com/demo/upimesh/
    ├── UpiMeshApplication.java          # Spring Boot main
    ├── model/                           # Domain entities
    ├── crypto/                          # Encryption/decryption
    ├── service/                         # Business logic
    ├── controller/                      # REST endpoints
    └── config/                          # Spring configuration
```

#### Running Tests
```bash
# All tests
mvnw test

# Concurrency test (3 bridges simultaneous)
mvnw test -Dtest=IdempotencyConcurrencyTest
```

---

## 🏗️ Repository Structure

```
Projects/
├── README.md                                  # This file
├── .gitignore                                 # Comprehensive ignore rules
├── Medical-Chatbot-main/
│   └── Medical-Chatbot-main/
│       ├── medibot.py
│       ├── requirements.txt
│       └── ... (Python LLM project)
├── PacketAnalyzer-java/
│   ├── README.md
│   └── PacketAnalyzer/
│       ├── pom.xml
│       └── src/ (Java DPI project)
└── UPI_Without_Internet-main/
    ├── README.md
    ├── pom.xml
    ├── mvnw / mvnw.cmd
    └── src/ (Spring Boot project)
```

---

## 🛠️ Technology Stack Summary

| Project | Language | Framework | Key Tech |
|---------|----------|-----------|----------|
| Medical Chatbot | Python 3.11+ | Streamlit | LangChain, FAISS, Groq API |
| PacketAnalyzer | Java 17+ | Maven | No dependencies (pure Java) |
| UPI Without Internet | Java 17+ | Spring Boot 3.3 | H2, JPA, Cryptography |

---

## 📦 Dependencies & Requirements

### Medical Chatbot
- Python 3.11 or higher
- pip (package manager)
- Groq API key (free at https://console.groq.com)

### PacketAnalyzer
- Java 17 or later
- Maven 3.6.0 or later
- **No runtime dependencies**

### UPI Without Internet
- Java 17 or later
- Maven 3.6.0 or later (via mvnw wrapper)
- **No external database required** (uses embedded H2)

---

## 🚀 Quick Start - All Projects

### Medical Chatbot
```bash
cd Medical-Chatbot-main/Medical-Chatbot-main
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo "GROQ_API_KEY=your_key" > .env
python create_memory_for_llm.py
streamlit run medibot.py
```

### PacketAnalyzer
```bash
cd PacketAnalyzer-java/PacketAnalyzer
mvn clean package
java -jar target/PacketAnalyzer.jar input.pcap output.pcap
```

### UPI Without Internet
```bash
cd UPI_Without_Internet-main
mvnw spring-boot:run  # or ./mvnw on Mac/Linux
# Open http://localhost:8080
```

---

## 📚 Documentation

Each project includes its own detailed README:
- [Medical Chatbot](./Medical-Chatbot-main/Medical-Chatbot-main/README.md)
- [PacketAnalyzer](./PacketAnalyzer-java/README.md)
- [UPI Without Internet](./UPI_Without_Internet-main/README.md)

---

## 🔑 Key Concepts Demonstrated

### Medical Chatbot
- **RAG (Retrieval-Augmented Generation)** - Combining semantic search with LLM
- **Vector Embeddings** - Converting text to semantic representations
- **LLM Integration** - Using external APIs for generation
- **Prompt Engineering** - Structuring context for better responses

### PacketAnalyzer
- **Deep Packet Inspection** - Layer 2-4 protocol parsing
- **Network Flow Tracking** - O(1) state management
- **Domain Extraction** - TLS SNI, HTTP Host, DNS queries
- **Zero Dependencies** - Pure Java implementation

### UPI Without Internet
- **Hybrid Encryption** - RSA-OAEP + AES-GCM
- **Idempotency** - Exactly-once semantics with atomic operations
- **Mesh Networks** - Distributed packet routing
- **Cryptographic Authentication** - GCM tags for integrity
- **Transaction Deduplication** - Hash-based duplicate detection

---

## 🧪 Testing

Each project includes tests:

- **Medical Chatbot:** Manual testing via Streamlit UI
- **PacketAnalyzer:** Built-in validation and error handling
- **UPI Without Internet:** 
  - Unit tests for encryption/decryption
  - Concurrency tests for duplicate handling
  - Tamper detection tests

---

## 🔒 Security Considerations

### Medical Chatbot
- API key should be stored in `.env` (not committed)
- PDF documents should be vetted before processing
- Consider rate limiting in production

### PacketAnalyzer
- No network access required (pure local processing)
- Safe handling of malformed packets
- No execution of untrusted code

### UPI Without Internet
- RSA keys regenerated on startup (development only)
- GCM tags prevent tampering
- Timestamp-based replay protection
- Atomic operations ensure consistency

---

## 📝 License

Each project maintains its own license as specified in individual README files.

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Follow project-specific guidelines
4. Submit a pull request

---

## 💡 Use Cases

### Medical Chatbot
- Customer support for healthcare queries
- Medical education and training
- Patient information portal
- 24/7 availability healthcare assistant

### PacketAnalyzer
- Network security and threat detection
- Content filtering and monitoring
- Network performance analysis
- Compliance and audit logging
- DPI-based QoS management

### UPI Without Internet
- Offline payment systems
- Disaster recovery scenarios
- Rural area payment solutions
- Blockchain/mesh network research
- Cryptocurrency and defi applications

---

## 📊 Project Statistics

| Metric | Medical Chatbot | PacketAnalyzer | UPI Without Internet |
|--------|-----------------|-----------------|----------------------|
| Language | Python | Java | Java |
| LOC | ~3,300 | ~2,500 | ~2,800 |
| Dependencies | 97 | 0 | ~15 |
| Setup Time | ~2 min | Immediate | Immediate |
| Memory (Runtime) | ~500MB | Streaming | ~100MB |
| Key Feature | RAG + LLM | DPI | Idempotency |

---

## 🎯 Learning Outcomes

After exploring these projects, you'll understand:

1. **AI/ML Development**
   - Building with LLMs and APIs
   - Vector databases and embeddings
   - RAG architectures

2. **Network Programming**
   - PCAP file formats
   - Protocol parsing
   - Flow tracking

3. **Distributed Systems**
   - Mesh networking
   - Idempotency patterns
   - Cryptographic authentication

4. **System Design**
   - High-performance processing
   - Thread-safe operations
   - End-to-end encryption

---

## 🐛 Troubleshooting

### Medical Chatbot
- **Vector store error:** Run `create_memory_for_llm.py` first
- **API key issue:** Verify `GROQ_API_KEY` in `.env`
- **PDF issues:** Ensure PDFs are valid and not encrypted

### PacketAnalyzer
- **Invalid PCAP:** Verify file format and byte order
- **Memory issues:** Process in smaller chunks
- **No apps detected:** Check PCAP contains HTTP/TLS traffic

### UPI Without Internet
- **Port in use:** Change `server.port` in `application.properties`
- **Build hangs:** Maven download in progress (2-3 min first run)
- **Tests flaky:** Timing-sensitive concurrency tests

---

## 📞 Support

For issues and questions:
- Check individual project README files
- Review code comments
- Verify environment setup and dependencies
- Open an issue on GitHub

---

## 🌟 Highlights

- **Production-Ready Code** - Best practices throughout
- **Comprehensive Documentation** - Detailed READMEs and comments
- **Real-World Applications** - Practical use cases
- **Modern Technologies** - Latest frameworks and tools
- **Security First** - Cryptography and best practices
- **Performance Focused** - Optimized algorithms and data structures

---

**Repository:** https://github.com/rishisingh9152-cyber/Projects-

Last Updated: May 19, 2026

---

*This repository showcases advanced software engineering concepts, cryptography, network programming, and AI/ML integration in production-grade applications.*
