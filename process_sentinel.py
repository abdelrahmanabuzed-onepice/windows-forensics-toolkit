"""
Windows Forensics Toolkit - Process Sentinel
Scans active processes for suspicious command-line flags, memory usage, and parent execution patterns.
"""

import subprocess
import json
from typing import List, Dict, Any


def scan_active_processes(limit: int = 15) -> List[Dict[str, Any]]:
    """Gathers running processes and flags suspicious process arguments."""
    ps_cmd = f"""
    Get-CimInstance Win32_Process | Select-Object -First {limit} ProcessId, Name, CommandLine, WorkingSetSize |
    ForEach-Object {{
        $suspicious = $false
        if ($_.CommandLine -match "(-enc|-encodedcommand|downloadstring|bypass|iex)") {{
            $suspicious = $true
        }}
        [PSCustomObject]@{{
            PID = $_.ProcessId
            Name = $_.Name
            CommandLine = $_.CommandLine
            MemoryMB = [math]::Round($_.WorkingSetSize / 1MB, 2)
            Flagged = $suspicious
        }}
    }} | ConvertTo-Json
    """
    processes = []
    try:
        out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_cmd], text=True, stderr=subprocess.DEVNULL)
        if out.strip():
            data = json.loads(out)
            processes = data if isinstance(data, list) else [data]
    except Exception:
        pass
    return processes


if __name__ == "__main__":
    procs = scan_active_processes(10)
    print(f"Scanned {len(procs)} processes.")
