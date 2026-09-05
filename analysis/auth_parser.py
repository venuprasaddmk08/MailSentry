import re


def parse_auth_results(auth_header: str | None) -> dict:
    if not auth_header:
        return {"spf": "none", "dkim": "none", "dmarc": "none"}

    def extract(mechanism):
        match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
        return match.group(1).lower() if match else "none"

    return {
        "spf": extract("spf"),
        "dkim": extract("dkim"),
        "dmarc": extract("dmarc"),
    }