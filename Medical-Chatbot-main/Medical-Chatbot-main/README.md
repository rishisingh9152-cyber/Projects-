# Medical Chatbot

A retrieval-augmented generation (RAG) chatbot powered by LangChain, FAISS, and Groq's LLM for answering medical queries based on PDF documents.

## Overview

This project implements an intelligent medical chatbot that processes PDF documents, creates semantic embeddings, and uses a retrieval-augmented generation pipeline to answer medical questions. The chatbot combines:

- **Document Processing**: Loads and chunks PDF documents from a data folder
- **Vector Embeddings**: Uses HuggingFace sentence transformers for semantic understanding
- **Vector Database**: FAISS for efficient similarity search
- **LLM Integration**: Groq's LLaMA 3.1 8B model for answer generation
- **Web Interface**: Streamlit-based UI for interactive conversations

## Features

- 📄 **PDF Document Processing** - Automatically loads and processes PDF files from the `data/` directory
- 🔍 **Semantic Search** - Uses FAISS vector database for fast similarity search
- 🤖 **AI-Powered Responses** - Leverages Groq's LLaMA 3.1 model for intelligent answers
- 💬 **Conversational Interface** - Interactive Streamlit web application with chat history
- 📚 **Context-Aware** - Retrieves relevant document chunks to ground responses
- ⚡ **Optimized Performance** - Caches vector store for faster inference

## Prerequisites

- Python 3.11 or higher
- Groq API key (obtain from [Groq Console](https://console.groq.com))
- PDF documents in the `data/` directory

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Medical-Chatbot-main
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   Create a `.env` file in the project root:
   ```
   GROQ_API_KEY=your_groq_api_key_here
   ```

## Project Structure

```
Medical-Chatbot-main/
├── medibot.py                      # Main Streamlit chatbot application
├── create_memory_for_llm.py       # Script to create and store vector embeddings
├── connect_memory_with_llm.py     # Script to test the RAG chain
├── data/                           # Directory for PDF documents (create if needed)
├── vectorstore/
│   └── db_faiss/                  # FAISS vector database (auto-generated)
├── requirements.txt                # Python dependencies
├── pyproject.toml                 # Project configuration
└── README.md                       # This file
```

## Quick Start

### Step 1: Prepare Your Data

Place your medical PDF documents in the `data/` directory:
```bash
mkdir data
# Copy your PDF files to the data/ directory
```

### Step 2: Create Vector Embeddings

Run the memory creation script to process PDFs and build the vector database:
```bash
python create_memory_for_llm.py
```

This script will:
- Load all PDF files from `data/` directory
- Split documents into chunks (500 character chunks with 50 character overlap)
- Create semantic embeddings using HuggingFace's `sentence-transformers/all-MiniLM-L6-v2`
- Store embeddings in FAISS database at `vectorstore/db_faiss`

### Step 3: Launch the Chatbot

Start the Streamlit web application:
```bash
streamlit run medibot.py
```

The application will open at `http://localhost:8501`

## Usage

1. Open the Streamlit interface in your browser
2. Type your medical query in the chat input
3. The chatbot will:
   - Search the vector database for relevant document chunks
   - Pass them to the LLM along with your question
   - Generate and display a contextual answer
4. View chat history within the same session

## Configuration

### Model Settings (in `medibot.py`)
- **Model**: `llama-3.1-8b-instant` (customizable)
- **Temperature**: 0.5 (controls response creativity)
- **Max Tokens**: 512 (maximum response length)
- **Search Results**: Top 3 most relevant chunks

### Chunking Settings (in `create_memory_for_llm.py`)
- **Chunk Size**: 500 characters
- **Chunk Overlap**: 50 characters

## Testing

To test the RAG chain without the web interface:
```bash
python connect_memory_with_llm.py
```

This script allows you to input queries and see:
- The generated answer
- Source documents and metadata used

## Key Technologies

| Component | Technology |
|-----------|-----------|
| Document Processing | LangChain, PyPDF |
| Embeddings | Sentence Transformers (HuggingFace) |
| Vector Database | FAISS |
| LLM | Groq (LLaMA 3.1 8B) |
| Web Framework | Streamlit |
| ML Libraries | scikit-learn, scipy, transformers |

## Architecture

```
PDFs → Document Loader → Text Splitter → Embeddings
                                           ↓
                                         FAISS
                                           ↓
User Query → Embedding → FAISS Search → Context + Query
                                           ↓
                                      Groq LLM
                                           ↓
                                        Answer
```

## Performance

- **Vector Store Caching**: FAISS database is cached with `@st.cache_resource` for faster subsequent queries
- **Efficient Retrieval**: Returns only top 3 most relevant chunks to balance quality and speed
- **Asynchronous LLM**: Groq's API provides fast inference with reasonable latency

## Troubleshooting

### Vector Store Loading Error
- Ensure `vectorstore/db_faiss` exists by running `create_memory_for_llm.py`
- Check that embeddings were successfully created

### API Key Issues
- Verify `GROQ_API_KEY` is correctly set in `.env`
- Check your API key has active credits at [Groq Console](https://console.groq.com)

### PDF Processing Issues
- Ensure PDFs are valid and not encrypted
- Check that PDF files are in the `data/` directory with `.pdf` extension

### Memory Issues
- Large PDF collections may require increased system memory
- Consider processing in batches if needed

## Dependencies

Key dependencies include:
- **langchain**: LLM framework and RAG orchestration
- **faiss-cpu**: Vector similarity search
- **sentence-transformers**: Semantic embeddings
- **streamlit**: Web interface
- **groq**: Groq API client
- **pypdf**: PDF parsing

See `requirements.txt` for complete dependency list.

## Future Enhancements

- Multi-language support
- Document upload through web interface
- Query feedback and improvement loop
- Source citation with page numbers
- Conversation persistence
- Multi-document RAG improvements

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]

## Support

For issues and questions:
- Check the troubleshooting section
- Review the code comments in each script
- Verify your environment setup and API keys