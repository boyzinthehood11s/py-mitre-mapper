from datetime import datetime

MITRE_MAPPING = {
    "ssh": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "id": "T1110"
    },
    "http": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "id": "T1190"
    },
    "ftp": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "id": "T1110"
    }
}


def analyze_services(services):
    findings = []

    for service in services:
        for key in MITRE_MAPPING:
            if key in service.lower():
                findings.append({
                    "service": service,
                    "tactic": MITRE_MAPPING[key]["tactic"],
                    "technique": MITRE_MAPPING[key]["technique"],
                    "id": MITRE_MAPPING[key]["id"]
                })
    return findings


if __name__ == "__main__":
    services_detected = [
        "22/tcp open ssh",
        "80/tcp open http"
    ]

    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = analyze_services(services_detected)

    print("\n[ MITRE ATT&CK Mapping ]\n")
    for r in results:
        print(f"{r['service']} -> {r['tactic']} | {r['technique']} ({r['id']})")

    with open("output/mitre_report.txt", "w") as f:
        f.write("MITRE ATT&CK Mapping Report\n")
        f.write("===========================\n\n")
        f.write(f"Date: {date}\n\n")

        for r in results:
            f.write(
                f"{r['service']} -> "
                f"{r['tactic']} | "
                f"{r['technique']} ({r['id']})\n"
            )
