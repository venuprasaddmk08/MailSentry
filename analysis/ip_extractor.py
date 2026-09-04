import re

IPV4_PATTERN = re.compile(
    r"\[?("
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r")\]?"
)

def extract_ips(received_chain: list[str]) -> list[str]:
    ips = []
    for line in received_chain:
        matches = IPV4_PATTERN.findall(line)
        for ip in matches:
            if ip not in ips and not is_private_ip(ip):
                ips.append(ip)
    return ips

def is_private_ip(ip: str) -> bool:
    octets = ip.split(".")
    first = int(octets[0])
    second = int(octets[1])
    return (
        first == 10
        or (first == 172 and 16 <= second <= 31)
        or (first == 192 and second == 168)
        or first == 127
    )