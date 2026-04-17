from semgrep_scan import run_semgrep
from zap_scan import run_zap
from headers_check import check_headers
from report import generate_report

def main():
    print("=== SecureFlow ===")
    print("1. Run SAST (Semgrep)")
    print("2. Run DAST (ZAP)")
    print("3. Run Both")

    choice = input("Enter choice: ")

    if choice == "1":
        code_path = input("Enter code folder path for SAST: ")

        print("\n[+] Running SAST...")
        semgrep_results = run_semgrep(code_path)

        generate_report(
            code_path,
            "N/A",
            semgrep_results,
            "N/A",
            {}
        )

    elif choice == "2":
        url = input("Enter URL for DAST: ")

        if not url.startswith("http"):
            url = "http://" + url

        print("\n[+] Running DAST...")
        zap_result = run_zap(url)

        print("[+] Checking HTTP Security Headers...")
        header_data = check_headers(url)

        generate_report(
            "N/A",
            url,
            [],
            zap_result.get("report"),
            header_data
        )

    elif choice == "3":
        code_path = input("Enter code folder path for SAST: ")
        url = input("Enter URL for DAST: ")

        if not url.startswith("http"):
            url = "http://" + url

        print("\n[+] Running SAST...")
        semgrep_results = run_semgrep(code_path)

        print("[+] Running DAST...")
        zap_result = run_zap(url)

        print("[+] Checking HTTP Security Headers...")
        header_data = check_headers(url)

        generate_report(
            code_path,
            url,
            semgrep_results,
            zap_result.get("report"),
            header_data
        )

    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()