import requests

def check_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers

        findings = []
        analysis = []

        # Security headers reference
        required_headers = {
            "Content-Security-Policy": "Prevents XSS attacks",
            "X-Frame-Options": "Prevents clickjacking",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "Strict-Transport-Security": "Enforces HTTPS",
            "Referrer-Policy": "Controls referrer leakage",
            "Permissions-Policy": "Restricts browser features"
        }

        # Check missing headers
        for header, desc in required_headers.items():
            if header not in headers:
                findings.append({
                    "header": header,
                    "risk": desc
                })
                analysis.append(f"Missing {header} → {desc}")

        # Info leakage checks
        if "Server" in headers:
            analysis.append("Server header exposed → potential information leakage")

        if "X-Powered-By" in headers:
            analysis.append("X-Powered-By header exposed → technology disclosure")

        return {
            "findings": findings,
            "analysis": analysis,
            "status_code": response.status_code,
            "headers": dict(headers),
            "url": url
        }

    except Exception as e:
        return {"error": str(e)}