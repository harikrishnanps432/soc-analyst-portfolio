import sys
import re
import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"']+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")

SUSPICIOUS = [
    "urgent", "verify your account", "password", "suspended",
    "click here", "payment", "invoice", "security alert"
]

def urls(text):
    return URL_RE.findall(text or "")

def iocs(text):
    found_urls = urls(text)
    domains = []
    for u in found_urls:
        try:
            host = urlparse(u).hostname
            if host:
                domains.append(host)
        except Exception:
            pass
    return {
        "urls": sorted(set(found_urls)),
        "domains": sorted(set(domains)),
        "ips": sorted(set(IP_RE.findall(text or ""))),
        "hashes": sorted(set(HASH_RE.findall(text or "")))
    }

def analyze(filename):
    with open(filename, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    name, address = parseaddr(msg.get("From", ""))
    subject = msg.get("Subject", "")
    auth = msg.get("Authentication-Results", "")
    body = ""
    attachments = []

    for part in msg.walk():
        if part.is_attachment():
            data = part.get_payload(decode=True) or b""
            attachments.append(
                (part.get_filename() or "unknown",
                 hashlib.sha256(data).hexdigest())
            )
        elif part.get_content_type() == "text/plain":
            try:
                body += part.get_content() + "\n"
            except Exception:
                pass

    text = subject + "\n" + body + "\n" + str(msg)
    lower = text.lower()
    indicators = []

    for word in SUSPICIOUS:
        if word in lower:
            indicators.append("Suspicious phrase: " + word)

    if urls(body):
        indicators.append("Embedded URL(s) found")
    if attachments:
        indicators.append("Attachment(s) found")

    for key in ("spf", "dkim", "dmarc"):
        m = re.search(r"\b" + key + r"=([a-zA-Z]+)", auth, re.I)
        if m:
            indicators.append(key.upper() + ": " + m.group(1).lower())

    score = len(indicators)
    classification = "Phishing" if score >= 4 else ("Suspicious" if score >= 2 else "Legitimate")

    print("=" * 55)
    print("PHISHING EMAIL ANALYZER")
    print("=" * 55)
    print("From           :", name, "<" + address + ">")
    print("Subject        :", subject)
    print("Classification :", classification)
    print("Risk score     :", score)

    print("\nIndicators:")
    for x in indicators:
        print("-", x)

    print("\nIOCs:")
    for key, values in iocs(text).items():
        print(key.upper() + ":")
        for value in values:
            print("  -", value)

    print("\nAttachments:")
    for filename, sha256 in attachments:
        print("  -", filename, "| SHA256:", sha256)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <email.eml>")
        raise SystemExit(1)
    analyze(sys.argv[1])
