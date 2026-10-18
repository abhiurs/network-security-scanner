def analyze_risk(service_result):
    service = service_result["service"].lower()
    port = service_result["port"]

    if service == "telnet" or port == 23:
        return {
            "risk_level": "HIGH",
            "reason": "Telnet is an unencrypted remote access protocol.",
        }

    elif service == "ftp" or port == 21:
        return {
            "risk_level": "MEDIUM",
            "reason": "FTP may transmit credentials and data without encryption.",
        }

    elif service in ["microsoft-ds", "netbios-ssn"] or port == 445:
        return {
            "risk_level": "MEDIUM",
            "reason": "SMB should be restricted to trusted networks and properly secured.",
        }

    elif service == "ssh" or port == 22:
        return {
            "risk_level": "LOW",
            "reason": "SSH provides encrypted remote administration; configuration should still be reviewed.",
        }

    elif service == "http" or port == 80:
        return {"risk_level": "LOW", "reason": "HTTP traffic is not encrypted."}

    elif service == "https" or port == 443:
        return {
            "risk_level": "INFO",
            "reason": "HTTPS provides encrypted web communication.",
        }

    else:
        return {
            "risk_level": "INFO",
            "reason": "No specific basic risk rule was identified for this service.",
        }


if __name__ == "__main__":
    test_result = {
        "port": 445,
        "protocol": "tcp",
        "state": "open",
        "service": "microsoft-ds",
        "product": "",
        "version": "",
    }

    risk = analyze_risk(test_result)

    print("Risk Level:", risk["risk_level"])
    print("Reason:", risk["reason"])
