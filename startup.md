# CipherVault - Startup Guide

This document provides instructions on how to start and run the CipherVault project locally.

---

## Quick Start Overview

CipherVault consists of two primary local applications:

| Application | Technology | Default URL | Entrypoint Command |
| :--- | :--- | :--- | :--- |
| **CipherVault Web Edition (Accounts & Hosted Transfers)** | Flask + Vanilla JS | [http://localhost:8502](http://localhost:8502) | `.\.venv\Scripts\python.exe hosted_app.py` |
| **CipherVault Classic Dashboard** | Streamlit | [http://localhost:8501](http://localhost:8501) | `.\.venv\Scripts\python.exe -m streamlit run app.py` |

---

## 1. Prerequisites & Environment Setup

Ensure you are in the project root (`c:\IS Lab Project`).

### Virtual Environment
If `.venv` is already set up, you do not need to recreate it. Otherwise:
```powershell
Set-Location 'C:\IS Lab Project'
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

---

## 2. Running the Applications

### Option A: Start the Web Edition (Accounts, Transfers, Analysis)
This runs the lightweight Flask server with the modern responsive dashboard on port 8502.
```powershell
.\.venv\Scripts\python.exe hosted_app.py
```
- **Access**: Open [http://localhost:8502](http://localhost:8502) in your browser.
- **Multi-user Testing**: Open a regular tab and an incognito window to simulate transfers between two accounts (e.g., Alice & Bob).
- **Health Check**: [http://127.0.0.1:8502/health](http://127.0.0.1:8502/health)

### Option B: Start the Classic Streamlit Dashboard
This runs the full original cryptographic benchmark and analysis dashboard on port 8501.
```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```
- **Access**: Open [http://localhost:8501](http://localhost:8501) in your browser.
- **Health Check**: [http://127.0.0.1:8501/_stcore/health](http://127.0.0.1:8501/_stcore/health)

### Option C: Run Both Simultaneously
Both applications can run concurrently in separate terminal windows or as background processes without port conflicts.

---

## 3. Testing & Verification

Run the test suite to verify cryptographic operations and server startup:
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```
