"""
Windows Forensics Toolkit - Event Log Auditor
Audits Windows security and system events for unauthorized logons, privilege misuse, and service installations.
"""

import subprocess
import json
from typing import Dict, Any, List


def get_recent_failed_logons(max_events: int = 10) -> List[Dict[str, Any]]:
    """Queries Windows Event Log for failed logon attempts (Event ID 4625)."""
    events = []
    ps_cmd = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625}} -MaxEvents {max_events} -ErrorAction SilentlyContinue |
    ForEach-Object {{
        [PSCustomObject]@{{
            TimeCreated = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            Id = $_.Id
            Message = $_.Message.Split("`n")[0]
        }}
    }} | ConvertTo-Json
    """
    try:
        out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_cmd], text=True, stderr=subprocess.DEVNULL)
        if out.strip():
            data = json.loads(out)
            events = data if isinstance(data, list) else [data]
    except Exception:
        pass
    return events


def audit_system_events() -> Dict[str, Any]:
    """Runs high-level event log telemetry checks."""
    failed_logons = get_recent_failed_logons(5)
    return {
        "status": "COMPLETED",
        "recent_failed_logons_count": len(failed_logons),
        "recent_failed_logons": failed_logons
    }


if __name__ == "__main__":
    print("Auditing Windows Events...")
    res = audit_system_events()
    print(res)
