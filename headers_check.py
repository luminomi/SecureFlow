import requests
import json
import os
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# 🔹 LOAD RULES FROM JSON
def load_rules():
    base_path = os.path.dirname(__file__)
    file_path = os.path.join(base_path, "headers_rules.json")  # <-- matches your file name

    with open(file_path, "r") as f:
        return json.load(f)


# 🔹 MAIN FUNCTION
def check_headers(url):
    try:
        rules = load_rules()

        response = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
            verify=False
        )

        headers = response.headers

        findings = []
        analysis = []

        for header, rule in rules.items():

            # Missing security headers
            if header not in headers and rule["category"] != "Information Disclosure":
                findings.append({
                    "header": header,
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "risk": rule["risk"],
                    "recommendation": rule["recommendation"]
                })

                analysis.append(f"Missing {header} → {rule['risk']}")

            # Info disclosure headers present
            if header in headers and rule["category"] == "Information Disclosure":
                findings.append({
                    "header": header,
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "risk": rule["risk"],
                    "recommendation": rule["recommendation"]
                })

                analysis.append(f"{header} exposed → {rule['risk']}")

        return {
            "findings": findings,
            "analysis": analysis,
            "status_code": response.status_code,
            "headers": dict(headers),
            "url": url
        }

    except Exception as e:
        print("ERROR in headers_check:", e)
        return {"error": str(e)}