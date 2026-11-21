"""
Windows Forensics Toolkit - Artifact & URL Defanger
Sanitizes malicious URLs, IPs, and email indicators so they can be safely documented in audit reports.
"""

import re


def defang_indicator(text: str) -> str:
    """Defangs URLs, domains, and IP addresses to prevent accidental clicks."""
    # Replace http/https
    text = re.sub(r'https?://', lambda m: m.group(0).replace('http', 'hxxp'), text, flags=re.IGNORECASE)
    # Defang dots in domains and IPs: e.g. google.com -> google[.]com
    text = re.sub(r'(\w+)\.(\w+)', r'\1[.]\2', text)
    # Defang @ in emails
    text = text.replace('@', '[at]')
    return text


def refang_indicator(text: str) -> str:
    """Restores defanged indicators back to original state."""
    text = re.sub(r'hxxps?://', lambda m: m.group(0).replace('hxxp', 'http'), text, flags=re.IGNORECASE)
    text = text.replace('[.]', '.')
    text = text.replace('[at]', '@')
    return text


if __name__ == "__main__":
    sample = "Download payload from http://malicious-site.example.com/bad.exe or contact evil@phish.com"
    defanged = defang_indicator(sample)
    print("Original: ", sample)
    print("Defanged: ", defanged)
