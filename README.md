# SecureFlow

**SecureFlow** is an automated security assessment tool designed to streamline both Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST).

## 📂 Project Structure

The project is organized into two main components:

- **`backend/`**: Contains the core security scanning logic and CLI tool.
  - `main.py`: CLI entry point.
  - `semgrep_scan.py`: SAST logic.
  - `zap_scan.py`: DAST logic.
  - `headers_check.py`: HTTP header analysis.
  - `report.py`: Reporting logic.
  - `dashboard.py`: HTML dashboard generator.
- **`frontend/`**: Contains the web interface.
  - `app.py`: Flask web server.
  - `templates/`: HTML UI templates.

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

### 1. Command Line Interface (CLI)
Run the core scanner from the `backend` directory:
```bash
cd backend
python3 main.py
```

### 2. Web Interface
Start the web server from the root directory:
```bash
python3 frontend/app.py
```
Then navigate to `http://127.0.0.1:5000` in your browser.

## 📝 Roadmap
- [ ] Full Flask/FastAPI integration.
- [ ] Support for more languages.
- [ ] CI/CD integration.

## ⚖️ License
MIT License.
