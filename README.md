# SecureFlow

**SecureFlow** is an automated security assessment tool designed to streamline both Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST).

## 📂 Project Structure

- **`backend/`**: Core scanning logic and CLI tool.
  - `main.py`: CLI entry point.
  - `semgrep_scan.py`, `zap_scan.py`, `headers_check.py`: Scanning modules.
  - `report.py`, `dashboard.py`: Reporting and visualization.
- **`frontend/`**: Web application.
  - `app.py`: Flask server.
  - `templates/`: Web UI templates (Dashboard, Reports History, Details).

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
- Run new scans.
- View real-time results.
- **Browse Scan History**: Access historical reports and detailed findings.

### 2. Command Line Interface (CLI)
Run the core scanner from the `backend` directory:
```bash
cd backend
python3 main.py
```

## 📝 Roadmap
- [ ] Export reports to PDF/JSON.
- [ ] Support for JS, Go, and Ruby SAST.
- [ ] GitHub Actions integration.

## ⚖️ License
MIT License.
