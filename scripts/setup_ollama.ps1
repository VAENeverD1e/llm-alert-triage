# PowerShell Setup Script for Ollama on Windows
# Checks installation, installs via winget if missing, starts service, and pulls required models.

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Setting up Ollama for LLM Alert Triage   " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Check if Ollama CLI is installed
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Ollama CLI not found in PATH." -ForegroundColor Yellow
    Write-Host "[*] Attempting to install via winget..." -ForegroundColor Cyan
    try {
        winget install -e --id Ollama.Ollama --accept-source-agreements --accept-package-agreements
        Write-Host "[+] Ollama installed successfully! Please restart your terminal if 'ollama' is not recognized." -ForegroundColor Green
    } catch {
        Write-Host "[!] Winget installation failed or was cancelled." -ForegroundColor Red
        Write-Host "[!] Please manually download and install Ollama from: https://ollama.com/download/windows" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host "[+] Ollama CLI is already installed: $((Get-Command ollama).Source)" -ForegroundColor Green
}

# 2. Check if Ollama local service is running
Write-Host "[*] Checking if Ollama service is running on http://localhost:11434..." -ForegroundColor Cyan
try {
    $res = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -Method Get -TimeoutSec 3
    Write-Host "[+] Ollama service is active and responsive!" -ForegroundColor Green
} catch {
    Write-Host "[!] Ollama service is not responding. Starting Ollama in the background..." -ForegroundColor Yellow
    Start-Process "ollama" -ArgumentList "serve" -WindowStyle Hidden
    Start-Sleep -Seconds 3
}

# 3. Pull required models
$primaryModel = "llama3:8b"
$fallbackModel = "mistral:7b"
$lightweightModel = "llama3.2:3b"

Write-Host "`n[+] Recommended models for triage:" -ForegroundColor Cyan
Write-Host "  1. $primaryModel (Standard / Recommended for production accuracy)"
Write-Host "  2. $lightweightModel (Lightweight / Ultra-fast inference)"
Write-Host "  3. $fallbackModel (Alternative reasoning model)"

Write-Host "`n[*] Pulling primary model: $primaryModel..." -ForegroundColor Yellow
ollama pull $primaryModel

Write-Host "[*] Pulling lightweight model for fast local testing: $lightweightModel..." -ForegroundColor Yellow
ollama pull $lightweightModel

Write-Host "`n[+] Ollama setup completed successfully!" -ForegroundColor Green
Write-Host "[+] Local API is available at: http://localhost:11434" -ForegroundColor Green
