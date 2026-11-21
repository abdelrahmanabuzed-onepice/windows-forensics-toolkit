"""
Windows Forensics Toolkit - Unified CLI Entrypoint
"""

import sys
import argparse
from event_auditor import audit_system_events
from process_sentinel import scan_active_processes
from system_hardening import audit_host_defense
from file_defanger import defang_indicator


def main():
    parser = argparse.ArgumentParser(description="Windows Forensics & Incident Response Toolkit by Abdelrahman Abouzed")
    parser.add_argument("--audit-all", action="store_true", help="Run comprehensive system security audit")
    parser.add_argument("--defang", type=str, help="Defang a malicious URL/IP for safe reporting")
    parser.add_argument("--processes", action="store_true", help="Inspect running processes for suspicious arguments")
    
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("      WINDOWS FORENSICS & INCIDENT RESPONSE TOOLKIT")
    print("=" * 60)

    if args.defang:
        print(f"Original: {args.defang}")
        print(f"Defanged: {defang_indicator(args.defang)}")
        return

    if args.processes or args.audit_all:
        print("\n[+] Scanning Running Processes for Suspicious Flags:")
        procs = scan_active_processes(10)
        for p in procs:
            flag_str = "[FLAGGED]" if p.get("Flagged") else "[OK]"
            print(f"  {flag_str:<9} PID: {p.get('PID'):<6} Name: {p.get('Name'):<20} Mem: {p.get('MemoryMB')} MB")

    if args.audit_all or not sys.argv[1:]:
        print("\n[+] Host Defense Status:")
        defense = audit_host_defense()
        det = defense.get("details", {})
        print(f"  Antivirus Enabled:     {det.get('AntivirusEnabled')}")
        print(f"  Real-time Protection:  {det.get('RealTimeProtection')}")
        print(f"  Firewall Status:       Public: {det.get('FirewallPublic')}, Private: {det.get('FirewallPrivate')}")

        print("\n[+] Security Event Telemetry:")
        events = audit_system_events()
        print(f"  Recent Failed Logons:  {events.get('recent_failed_logons_count')}")

    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
