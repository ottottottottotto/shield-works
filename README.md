# Shield Works 🛡️

**Shield Works** is an advanced security evaluation engine designed for the SecureScope platform. It provides a unified interface for URL analysis, source code scanning, and binary logic auditing.

## 🚀 Professional Deployment

This repository is optimized for one-click deployment to **HuggingFace Spaces**, **Render**, or **Heroku**.

### Deployment Specs
- **SDK**: Docker
- **Default Port**: 7860 (HuggingFace/Cloud Standard)
- **Engine**: FastAPI (Python 3.11)

## 🛠️ Local Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ottottottottotto/shield-works.git
   cd shield-works
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch the Scanner**:
   - **Windows**: Run `Start_ShieldWorks.bat` for an automated setup and browser launch.
   - **Manual**: Run `python main.py` and access `http://localhost:8000`.

## 🔍 Key Features
- **Remote Surface Matrix**: Automated URL scanning for SSL/TLS and security headers.
- **Source Code SAST**: Pattern-based secret and vulnerability detection.
- **Binary Heuristics**: Deep-dive analysis of Software Binaries and APKs.
- **Historical Audit**: Persistent storage of security reports.

---
Built for Hackathon Demo ($0 Budget).
