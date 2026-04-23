# SecureFlow

**SecureFlow** is an automated security assessment tool designed to streamline both Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST).

## 📂 Project Structure

- **`backend/`**: Core scanning logic and CLI tool.
  - `main.py`: CLI entry point.
  - `semgrep_scan.py`, `zap_scan.py`, `headers_check.py`: Scanning modules.
  - `report.py`, `dashboard.py`: Reporting and visualization.
- **`frontend/`**: Web application.
  - `app.py`: Flask server.
  - `templates/`: Web UI templates (Dashboard, Reports History, Details, Documentation).
- **`Reports/`**: Directory where all generated text reports are stored.

## 🚀 Getting Started

### Prerequisites
1. **Python 3.8+**
2. **Semgrep CLI**: `pip install semgrep`
3. **OWASP ZAP**: [Download and install](https://www.zaproxy.org/download/).

### Installation
```bash
git clone https://github.com/Raghaverma/SecureFlow.git
cd SecureFlow
pip install -r requirements.txt
```

## 🖥️ Usage

### 1. Web Interface (Recommended)
Start the web server from the root directory:
```bash
python3 frontend/app.py
```
Navigate to `http://127.0.0.1:5000` to:
- Run new scans (SAST, DAST, or Both).
- **Scan History**: Browse and search through your historical scan results.
- **Documentation**: Access the built-in documentation page at `/docs`.

### 2. Command Line Interface (CLI)
Run the core scanner from the `backend` directory:
```bash
cd backend
python3 main.py
```

## 📊 Features
- **Centralized Reporting**: All scan results are automatically organized into the `Reports/` folder.
- **Dynamic Analysis**: Full integration with OWASP ZAP for live site scanning.
- **Static Analysis**: Deep source code scanning using Semgrep rules.
- **Security Headers**: Comprehensive check for HTTP security best practices.

## ⚖️ License
MIT License.
