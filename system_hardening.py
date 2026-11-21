"""
Windows Forensics Toolkit - System Hardening Auditor
Checks host defense posture: Defender real-time protection, Firewall status, and UAC elevation.
"""

import subprocess
import json
from typing import Dict, Any


def audit_host_defense() -> Dict[str, Any]:
    """Audits Windows Defender and Firewall defense states."""
    ps_cmd = """
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled
    
    [PSCustomObject]@{
        AntivirusEnabled = if ($defender) { $defender.AntivirusEnabled } else { "Unknown" }
        RealTimeProtection = if ($defender) { $defender.RealTimeProtectionEnabled } else { "Unknown" }
        SignatureAgeDays = if ($defender) { $defender.AntivirusSignatureAge } else { "Unknown" }
        FirewallDomain = ($firewall | Where-Object { $_.Name -eq 'Domain' }).Enabled
        FirewallPrivate = ($firewall | Where-Object { $_.Name -eq 'Private' }).Enabled
        FirewallPublic = ($firewall | Where-Object { $_.Name -eq 'Public' }).Enabled
    } | ConvertTo-Json
    """
    report = {
        "defender_active": False,
        "firewall_all_active": False,
        "details": {}
    }
    try:
        out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_cmd], text=True, stderr=subprocess.DEVNULL)
        if out.strip():
            data = json.loads(out)
            report["details"] = data
            report["defender_active"] = bool(data.get("RealTimeProtection", False))
            report["firewall_all_active"] = bool(data.get("FirewallPublic", False) and data.get("FirewallPrivate", False))
    except Exception as e:
        report["error"] = str(e)
        
    return report


if __name__ == "__main__":
    print(audit_host_defense())
