#!/usr/bin/env bash
# Environment setup script for local Ollama service & model pulling

set -e

echo "=========================================="
echo " Setting up Ollama for LLM Alert Triage  "
echo "=========================================="

if ! command -v ollama &> /dev/null; then
    echo "[!] Ollama command not found. Please install Ollama from https://ollama.ai/"
    exit 1
fi

echo "[+] Pulling primary model: llama3:8b..."
ollama pull llama3:8b

echo "[+] Pulling fallback model: mistral:7b..."
ollama pull mistral:7b

echo "[+] Ollama setup completed successfully!"
