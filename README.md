# SecureFlow

**SecureFlow** is an automated security assessment tool designed to streamline both Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST).

## 📂 Project Structure

- **`backend/`**: Core scanning logic and CLI tool.
  - `main.py`: CLI entry point.
  - `semgrep_scan.py`, `zap_scan.py`, `headers_check.py`: Multi-platform scanning engines.
  - `report.py`, `dashboard.py`: Reporting logic and refined HTML dashboard.
- **`frontend/`**: Modern web application.
  - `app.py`: Flask server with scan history and report viewer.
  - `templates/`: Professional UI templates (Dashboard, History, Documentation).
- **`Reports/`**: Centralized storage for all generated security reports.

## 🚀 Getting Started

### Prerequisites
1. **Python 3.8+**
2. **Semgrep CLI**: `pip install semgrep`
3. **OWASP ZAP**: [Download and install](https://www.zaproxy.org/download/). (Supports macOS, Windows, and Linux)

### Installation
```bash
git clone https://github.com/Raghaverma/SecureFlow.git
cd SecureFlow
pip install -r requirements.txt
```

## 🖥️ Usage

### 1. Web Interface (Recommended)
Launch the interactive dashboard:
```bash
python3 frontend/app.py
```
Navigate to `http://127.0.0.1:5000` to:
- **Execute Scans**: Run SAST, DAST, or unified assessments.
- **Browse History**: Access the `/reports` portal to view past findings.
- **Review Docs**: Detailed tool documentation available at `/docs`.

### 2. Command Line Interface (CLI)
Run the scanner via terminal:
```bash
cd backend
python3 main.py
```

## 📊 Core Capabilities
- **Cross-Platform Support**: Optimized for macOS, Windows, and Linux environments.
- **Smart Reporting**: Automatically aggregates findings into a sleek, responsive HTML dashboard.
- **Deep Scanning**: Utilizes Semgrep's powerful engine for source code analysis and OWASP ZAP for dynamic site testing.

## ⚖️ License
MIT License.
