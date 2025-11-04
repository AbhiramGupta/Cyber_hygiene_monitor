from flask import Flask, render_template, send_file, redirect, url_for, jsonify, request
import psutil
import subprocess
from fpdf import FPDF
from datetime import datetime
import json
import re
import winreg
from wifi_utils import check_wifi_password_strength, mask_password
import os
from pathlib import Path
import socket
import network_scan

app = Flask(__name__)

last_score = None
last_findings = None
last_recommendations = None
last_wifi_data = None
last_run_diff = None

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP",
    445: "SMB",
}

TEST_PORTS = {
    6000: "Custom Test Port 6000",
    7000: "Custom Test Port 7000"
}

# Ports that are considered default/system and should be reported but normally exempt from deductions.
DEFAULT_SYSTEM_PORTS = {445}

# Ports that are commonly associated with high-risk exposure / historically vulnerable services.
VULNERABLE_PORTS = {135, 137, 138, 139, 445, 3389}

### Helpers
def _to_bool(v):
    """Normalize various PowerShell outputs to Python bool."""
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "y", "on"):
        return True
    if s in ("false", "0", "no", "n", "off"):
        return False
    # default conservative
    return False

### WiFi extraction (unchanged)
def get_wifi_passwords():
    """Extract saved WiFi passwords from Windows"""
    try:
        profiles_data = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'profiles'], text=True
        )
        profiles = [line.split(":")[1].strip() for line in profiles_data.splitlines() if "All User Profile" in line]

        wifi_list = []
        for profile in profiles:
            try:
                profile_info = subprocess.check_output(
                    ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], text=True
                )
                key_line = [line for line in profile_info.splitlines() if "Key Content" in line]
                password = key_line[0].split(":")[1].strip() if key_line else None
                wifi_list.append({'SSID': profile, 'Password': password})
            except subprocess.CalledProcessError:
                wifi_list.append({'SSID': profile, 'Password': None})
        return wifi_list
    except Exception:
        return []

### Run history helpers (unchanged)
RUNS_DIR = Path(__file__).parent / "runs"
RUNS_DIR.mkdir(exist_ok=True)

def save_run(run_data: dict):
    """Save a run to the runs directory as timestamped JSON and return path."""
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    filename = RUNS_DIR / f"run_{ts}.json"
    with open(filename, 'w', encoding='utf-8') as fh:
        json.dump(run_data, fh, ensure_ascii=False, indent=2)
    return str(filename)

def load_last_run():
    runs = sorted(RUNS_DIR.glob('run_*.json'))
    if not runs:
        return None
    try:
        with open(runs[-1], 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return None

def compute_diff(old: dict, new: dict):
    """Compute a simple diff of findings between two run dicts.
    Returns dict with 'added' and 'removed' lists.
    """
    if not old:
        return {'added': new.get('findings', []), 'removed': []}
    old_set = set([f.lower().strip() for f in old.get('findings', [])])
    new_set = set([f.lower().strip() for f in new.get('findings', [])])
    added = [f for f in new.get('findings', []) if f.lower().strip() not in old_set]
    removed = [f for f in old.get('findings', []) if f.lower().strip() not in new_set]
    return {'added': added, 'removed': removed}

### Antivirus checker (improved robust parsing)
def check_antivirus_status():
    """Check Windows Defender status and other antivirus software (robust parsing)."""
    findings = []
    recommendations = []
    score_impact = 0

    # Only attempt Windows Defender checks on Windows
    try:
        import platform
        if platform.system().lower() != "windows":
            findings.append("Antivirus checks skipped (non-Windows host)")
            return findings, recommendations, score_impact
    except Exception:
        pass

    # Try JSON-based PowerShell call first (preferred)
    try:
        ps_cmd = [
            'powershell',
            '-NoProfile',
            '-Command',
            'Try { Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AMServiceEnabled | ConvertTo-Json -Compress } Catch { Write-Output "__MP_ERROR__"; exit 1 }'
        ]
        defender_json = subprocess.check_output(ps_cmd, text=True, stderr=subprocess.DEVNULL)
        if defender_json and defender_json.strip() != "__MP_ERROR__":
            try:
                status = json.loads(defender_json)
            except Exception:
                status = {}
            antivirus_enabled = _to_bool(status.get('AntivirusEnabled'))
            realtime_enabled = _to_bool(status.get('RealTimeProtectionEnabled'))
            ams_enabled = _to_bool(status.get('AMServiceEnabled'))

            # Antivirus engine
            if antivirus_enabled:
                findings.append("Windows Defender antivirus engine is ENABLED ✓")
            else:
                findings.append("Windows Defender antivirus engine is DISABLED")
                recommendations.append("Enable Windows Defender antivirus engine")
                score_impact -= 8

            # Real-time protection
            if realtime_enabled:
                findings.append("Windows Defender real-time protection is ENABLED ✓")
            else:
                findings.append("Windows Defender real-time protection is DISABLED")
                recommendations.append("Enable real-time protection to guard against active threats")
                score_impact -= 5

            # AMService
            if ams_enabled:
                findings.append("Windows Defender AMService appears to be running ✓")
            else:
                findings.append("Windows Defender service (AMService) appears to be OFF")
                recommendations.append("Verify Windows Defender service is running")
                score_impact -= 2
        else:
            # JSON path failed; fall through to text-based parsing below
            raise RuntimeError("Get-MpComputerStatus returned no usable JSON")
    except Exception:
        # Fallback: safer text-based parsing (avoid naive substring checks)
        try:
            defender_status = subprocess.check_output(
                ['powershell', '-NoProfile', '-Command', 'Get-MpComputerStatus | Format-List AntivirusEnabled,RealTimeProtectionEnabled,AMServiceEnabled'],
                text=True, stderr=subprocess.DEVNULL
            )
            # Parse lines like: AntivirusEnabled : True
            parsed = {}
            for line in defender_status.splitlines():
                if ':' in line:
                    k, v = line.split(':', 1)
                    parsed[k.strip().lower()] = v.strip()
            antivirus_enabled = _to_bool(parsed.get('antivirusenabled'))
            realtime_enabled = _to_bool(parsed.get('realtimeprotectionenabled'))
            ams_enabled = _to_bool(parsed.get('amserviceenabled'))

            if antivirus_enabled:
                findings.append("Windows Defender antivirus engine is ENABLED ✓")
            else:
                findings.append("Windows Defender antivirus engine is DISABLED")
                recommendations.append("Enable Windows Defender antivirus engine")
                score_impact -= 8

            if realtime_enabled:
                findings.append("Windows Defender real-time protection is ENABLED ✓")
            else:
                findings.append("Windows Defender real-time protection is DISABLED")
                recommendations.append("Enable real-time protection to guard against active threats")
                score_impact -= 5

            if ams_enabled:
                findings.append("Windows Defender AMService appears to be running ✓")
            else:
                findings.append("Windows Defender service (AMService) appears to be OFF")
                recommendations.append("Verify Windows Defender service is running")
                score_impact -= 2

        except Exception:
            findings.append("Could not check antivirus status (PowerShell check failed)")
            recommendations.append("Manually verify antivirus software is installed and enabled")
            score_impact -= 10

    # Finally, try to detect presence of other AV products via WMI (best-effort)
    try:
        wmi_output = subprocess.check_output(
            'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState',
            shell=True, text=True, stderr=subprocess.DEVNULL
        )
        if wmi_output and "No Instance(s) Available" not in wmi_output:
            # If there is output other than the default "No Instance(s) Available", record presence
            findings.append("Additional antivirus product(s) detected on system")
    except Exception:
        # ignore WMI errors - not critical
        pass

    return findings, recommendations, score_impact

### Windows updates (unchanged)
def check_windows_updates():
    """Check Windows update status"""
    findings = []
    recommendations = []
    score_impact = 0

    try:
        # Use Windows Update COM API via PowerShell to check for available updates
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ps1') as ps_file:
            ps_script = """
                try {
                    $Session = New-Object -ComObject Microsoft.Update.Session
                    $Searcher = $Session.CreateUpdateSearcher()
                    $SearchResult = $Searcher.Search("IsInstalled=0 AND Type='Software'")
                    $Count = $SearchResult.Updates.Count
                    Write-Output $Count
                    if ($Count -gt 0) {
                        $SearchResult.Updates | Select-Object -First 5 | ForEach-Object { Write-Output $_.Title }
                    }
                } catch {
                    Write-Output "ERROR: $($_.Exception.Message)"
                    exit 1
                }
            """
            ps_file.write(ps_script)
            ps_file.flush()
            script_path = ps_file.name
        try:
            update_output = subprocess.check_output(['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path], text=True)
        finally:
            import os
            try:
                os.unlink(script_path)  # Clean up the temporary script file
            except:
                pass  # Ignore cleanup errors
        lines = [l.strip() for l in update_output.splitlines() if l.strip()]
        if not lines:
            findings.append("Could not determine update status; manual check recommended")
            score_impact -= 2  # From 15 point base
        else:
            # Check if we got an error message
            if lines[0].startswith("ERROR:"):
                findings.append(f"Windows Update check failed: {lines[0]}")
                recommendations.append("Manually check for Windows updates")
                score_impact -= 5  # From 15 point base
            else:
                try:
                    count = int(lines[0])
                    if count == 0:
                        findings.append("No pending Windows updates ✓")
                    else:
                        findings.append(f"{count} pending Windows update(s) detected — showing up to 5 titles:")
                        for title in lines[1:]:
                            findings.append(f" - {title}")
                        recommendations.append("Open Settings → Update & Security and install pending updates")
                        # Deduct 3 points per missing update up to max 15 points
                        score_impact -= min(15, count * 3)
                except ValueError:
                    findings.append("Windows Update check returned unexpected output; manual verification recommended")
                    recommendations.append("Manually check for Windows updates")
                    score_impact -= 2

    except Exception:
        try:
            # Fallback to a conservative wmic check to avoid false positives
            update_output = subprocess.check_output(
                'wmic qfe list brief /format:table',
                shell=True, text=True
            )
            findings.append("Windows updates status checked")
        except:
            findings.append("Could not check Windows update status")
            recommendations.append("Manually check for Windows updates")
            score_impact -= 3

    return findings, recommendations, score_impact

### User accounts (unchanged)
def check_user_accounts():
    """Check user account security"""
    findings = []
    recommendations = []
    score_impact = 0

    try:
        # Check for users with admin privileges
        try:
            # Use PowerShell to get members of the Administrators group
            ps_members = subprocess.check_output(
                'powershell "Get-LocalGroupMember -Group \'Administrators\' | Select-Object -ExpandProperty Name"',
                shell=True, text=True
            )
            members = [line.strip() for line in ps_members.splitlines() if line.strip()]

            enabled_admins = []
            for member in members:
                acct = member.split('\\')[-1]
                try:
                    enabled_out = subprocess.check_output(
                        f'powershell "(Get-LocalUser -Name \"{acct}\" -ErrorAction SilentlyContinue).Enabled"',
                        shell=True, text=True
                    )
                    if 'True' in enabled_out:
                        enabled_admins.append(acct)
                except subprocess.CalledProcessError:
                    continue

            admin_count = len(enabled_admins)
            if admin_count > 1:
                findings.append(f"Multiple admin accounts detected ({admin_count} enabled local admin(s))")
                recommendations.append("Review and minimize local administrator accounts; keep only necessary admin users")
                score_impact -= 3

        except Exception:
            try:
                admin_users = subprocess.check_output(
                    'net localgroup administrators',
                    shell=True, text=True
                )
                admin_count = len([line for line in admin_users.splitlines() if line.strip() and "Members" not in line and "command completed" not in line])
                if admin_count > 2:
                    findings.append(f"Multiple admin accounts detected ({admin_count} total)")
                    recommendations.append("Review and minimize admin accounts")
                    score_impact -= 3
            except Exception:
                findings.append("Could not check administrator group membership")
                recommendations.append("Manually verify local Administrators group membership")
                score_impact -= 2

    except Exception:
        findings.append("Could not check user accounts")
        recommendations.append("Manually review user account settings")
        score_impact -= 3

    return findings, recommendations, score_impact

### Main quick scan with updated port logic
def scan_quick():
    """Quick scan: firewall, open ports, and antivirus status.
    Returns: (score, findings, recommendations)

    Fixed logic:
    - Build port -> {ips, pids} map from psutil.
    - Decide 'externally reachable' if any bind IP is:
        * 0.0.0.0, ::, '' (meaning all interfaces) OR
        * a non-loopback address (not 127.x.x.x and not ::1)
    - Only report and deduct for ports that are in COMMON_PORTS or TEST_PORTS
      (and NOT in DEFAULT_SYSTEM_PORTS).
    - Provide PID/process name where possible.
    """
    findings = []
    recommendations = []

    # Component maximum scores (total 100)
    max_scores = {
        'firewall': 30,   # Firewall security (30 points)
        'ports': 20,      # Port security (20 points)
        'updates': 15,    # Windows updates (15 points)
        'antivirus': 15,  # Antivirus status (15 points)
        'wifi': 20        # WiFi security (20 points)
    }

    # Initialize scores at 0 instead of maximum
    current_scores = {k: 0 for k in max_scores.keys()}

    # --- Firewall check (unchanged) ---
    try:
        fw_status = subprocess.check_output(
            'netsh advfirewall show allprofiles', shell=True, text=True
        ).lower()

        domain_on = private_on = public_on = False
        current_profile = None

        for line in fw_status.splitlines():
            line = line.strip()
            if line.startswith("domain profile settings"):
                current_profile = "domain"
            elif line.startswith("private profile settings"):
                current_profile = "private"
            elif line.startswith("public profile settings"):
                current_profile = "public"
            elif line.startswith("state") and current_profile:
                if "on" in line:
                    if current_profile == "domain":
                        domain_on = True
                    elif current_profile == "private":
                        private_on = True
                    elif current_profile == "public":
                        public_on = True

        if domain_on:
            current_scores['firewall'] += 12
            findings.append("Domain network firewall is ON ✓")
        else:
            findings.append("Domain network firewall is OFF")
            recommendations.append("Enable Domain firewall to protect domain networks")

        if private_on:
            current_scores['firewall'] += 9
            findings.append("Private network firewall is ON ✓")
        else:
            findings.append("Private network firewall is OFF")
            recommendations.append("Enable Private firewall to protect private networks")

        if public_on:
            current_scores['firewall'] += 9
            findings.append("Public network firewall is ON ✓")
        else:
            findings.append("Public network firewall is OFF")
            recommendations.append("Enable Public firewall to protect public networks")

    except Exception:
        findings.append("Could not check Firewall")
        recommendations.append("Manually verify firewall settings")
        # Keep score at 0 for firewall

    # --- Port scan: focus only on COMMON_PORTS and TEST_PORTS (exclude DEFAULT_SYSTEM_PORTS) ---
    try:
        # Build mapping: port -> {'ips': set(), 'pids': set()}
        port_map = {}
        for conn in psutil.net_connections(kind='tcp'):
            # only consider listening sockets
            status = getattr(conn, 'status', None)
            if status not in (psutil.CONN_LISTEN, 'LISTEN'):
                continue

            laddr = getattr(conn, 'laddr', None)
            if not laddr:
                continue

            # laddr can be an address tuple or an object with ip/port attributes
            try:
                ip = laddr.ip
                port = laddr.port
            except Exception:
                try:
                    ip, port = laddr
                except Exception:
                    continue

            if port is None:
                continue
            ip = (ip or '').strip()

            entry = port_map.setdefault(int(port), {'ips': set(), 'pids': set()})
            entry['ips'].add(ip)
            if getattr(conn, 'pid', None):
                entry['pids'].add(conn.pid)

        # Determine which ports are externally reachable:
        externally_reachable = set()
        for port, data in port_map.items():
            ips = data['ips']
            # If any ip is '' / '0.0.0.0' / '::' -> listening on all interfaces -> external
            if any(ip in ('', '0.0.0.0', '::') for ip in ips):
                externally_reachable.add(port)
                continue

            # If any bound IP is not a loopback (127.x.x.x or ::1) -> external
            non_loopback = False
            for ip in ips:
                if not ip:
                    continue
                low = ip.lower()
                if low == '::1' or low.startswith('127.'):
                    continue
                # also skip 'localhost' textual binding if it appears
                if low == 'localhost':
                    continue
                # treat any other IP as non-loopback
                non_loopback = True
                break
            if non_loopback:
                externally_reachable.add(port)

        # Interested ports = (COMMON ∪ TEST) - DEFAULT_SYSTEM_PORTS
        interested_ports = (set(COMMON_PORTS.keys()) | set(TEST_PORTS.keys())) - set(DEFAULT_SYSTEM_PORTS)

        # Collect exposed interesting ports (externally reachable and in interested_ports)
        exposed_interesting = []
        for p in sorted(interested_ports):
            if p in externally_reachable:
                exposed_interesting.append(p)

        PORT_DEDUCTION_PER_PORT = 4
        if exposed_interesting:
            # Deduct score proportional to exposed interesting ports
            deduction = len(exposed_interesting) * PORT_DEDUCTION_PER_PORT
            current_scores['ports'] = max(0, max_scores['ports'] - deduction)

            # Report them with PID/process name if available
            for p in exposed_interesting:
                info = port_map.get(p, {})
                pids = sorted(info.get('pids', []))
                proc_info = ""
                if pids:
                    try:
                        pid0 = pids[0]
                        proc_name = psutil.Process(pid0).name()
                        proc_info = f" (PID {pid0} / {proc_name})"
                    except Exception:
                        proc_info = f" (PID {pids[0]})"
                name = COMMON_PORTS.get(p) or TEST_PORTS.get(p) or f"Port {p}"
                findings.append(f"Open external port {p} ({name}) detected{proc_info}")
                recommendations.append(f"Close or firewall port {p} ({name}) if it is not required.")
        else:
            # No interesting common/test ports exposed externally -> full points for ports
            findings.append("No common/test ports exposed externally ✓")
            current_scores['ports'] = max(current_scores['ports'], max_scores['ports'])

    except Exception:
        findings.append("Could not check open ports")
        recommendations.append("Manually verify open ports")
        # Keep ports score at 0

    # --- Windows Updates (unchanged) ---
    update_findings, update_recs, update_impact = check_windows_updates()
    findings.extend(update_findings)
    recommendations.extend(update_recs)
    current_scores['updates'] = max(0, max_scores['updates'] + update_impact)

    # --- Antivirus status (unchanged) ---
    try:
        av_findings, av_recs, av_impact = check_antivirus_status()
        findings.extend(av_findings)
        recommendations.extend(av_recs)
        current_scores['antivirus'] = max(0, max_scores['antivirus'] + av_impact)
    except Exception:
        findings.append("Could not check antivirus status in quick scan")
        recommendations.append("Verify antivirus manually")
        # Keep antivirus score at 0

    # --- WiFi security (unchanged) ---
    if last_wifi_data:
        weak_wifi_count = 0
        wifi_score = max_scores['wifi']
        for wifi in last_wifi_data:
            pw = wifi.get('Password')
            if pw:
                result = check_wifi_password_strength(pw)
                wifi['strength_label'] = result.get('label')
                wifi['strength_score'] = result.get('score')
                wifi['strength_reasons'] = result.get('reasons', [])
                if result['label'] in ('very weak', 'weak'):
                    weak_wifi_count += 1
                    findings.append(f"Weak WiFi password detected for '{wifi['SSID']}' ({result['label']})")
                    for r in result.get('reasons', []):
                        recommendations.append(f"{wifi['SSID']}: {r}")
            else:
                wifi['strength_label'] = 'unknown'
                wifi['strength_score'] = 0
                wifi['strength_reasons'] = []
        if weak_wifi_count > 0:
            recommendations.append("Change weak WiFi passwords to stronger ones (use long passphrases with mixed characters)")
            wifi_score = max(0, wifi_score - (weak_wifi_count * 5))
        else:
            findings.append("WiFi passwords appear secure ✓")
        current_scores['wifi'] = wifi_score
    else:
        findings.append("No WiFi networks found to check")
        current_scores['wifi'] = max_scores['wifi']  # Full points if no WiFi to check

    # --- Final score calculation ---
    total_possible = sum(max_scores.values())
    total_earned = sum(current_scores.values())
    final_score = int(round((total_earned / total_possible) * 100)) if total_possible > 0 else 0
    final_score = max(0, min(100, final_score))

    return final_score, findings, recommendations


### High-level runner and endpoints
def run_scan(mode='quick'):
    """Run scans based on mode. Supported modes: 'quick', 'deep'.
    Returns (overall_score, aggregated_findings, aggregated_recommendations)
    """
    global last_wifi_data, last_run_diff
    last_wifi_data = get_wifi_passwords()

    aggregated_findings = []
    aggregated_recommendations = []
    component_scores = {}

    # Quick scan
    if mode in ('quick', 'deep'):
        # scan_quick now returns (score, findings, recommendations, metadata) or (score, findings, recommendations)
        res = scan_quick()
        if isinstance(res, tuple) and len(res) == 4:
            score, findings, recs, meta = res
        else:
            score, findings, recs = res
            meta = {}
        aggregated_findings.extend(findings)
        aggregated_recommendations.extend(recs)
        overall_score = score  # Use the normalized score from scan_quick

    # If scan_quick provided metadata about system hardening, use it; otherwise we can call checks once
    av_findings = []
    update_findings = []
    if 'meta' in locals() and isinstance(meta, dict):
        av_findings = meta.get('antivirus', [])
        update_findings = meta.get('updates', [])

    # Network device discovery (optional and lightweight)
    try:
        devices = network_scan.discover_devices()
    except Exception:
        devices = []

    # Prepare run data and save
    run_data = {
        'timestamp': datetime.now().isoformat(),
        'mode': mode,
        'findings': aggregated_findings,
        'recommendations': aggregated_recommendations,
        'score': overall_score,
        'system_hardening': {
            'antivirus': av_findings,
            'updates': update_findings
        },
        'network_devices': devices
    }
    last_path = save_run(run_data)

    # Compute diff against previous run (if any)
    prev = load_last_run()
    runs = sorted(RUNS_DIR.glob('run_*.json'))
    prev_run = None
    if len(runs) >= 2:
        try:
            with open(runs[-2], 'r', encoding='utf-8') as fh:
                prev_run = json.load(fh)
        except Exception:
            prev_run = None

    last_run_diff = compute_diff(prev_run, run_data)
    return overall_score, aggregated_findings, aggregated_recommendations

@app.route('/api/scan_history')
def api_scan_history():
    """Return last N scan summaries (timestamp and score) as JSON."""
    try:
        runs = sorted(RUNS_DIR.glob('run_*.json'))
        history = []
        max_items = int(request.args.get('n', 20))
        for p in runs[-max_items:]:
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    r = json.load(fh)
                    history.append({'timestamp': r.get('timestamp'), 'score': r.get('score', None)})
            except Exception:
                continue
        return jsonify(history)
    except Exception:
        return jsonify([])

@app.route("/")
def dashboard():
    global last_score, last_findings, last_wifi_data
    return render_template("dashboard.html", score=last_score, findings=last_findings, wifi_data=last_wifi_data)

@app.route("/scan")
def scan():
    global last_score, last_findings, last_recommendations
    last_score, last_findings, last_recommendations = run_scan()
    return redirect(url_for('dashboard'))

@app.route("/report")
def download_report():
    global last_score, last_findings, last_recommendations
    if last_score is None or last_findings is None:
        return redirect(url_for('dashboard'))

    pdf = FPDF()
    pdf.add_page()

    # Title and Header
    pdf.set_font("Arial", "B", 18)
    pdf.cell(0, 10, "Security Assessment Report", ln=True, align="C")
    pdf.ln(5)

    # Score visualization
    pdf.set_font("Arial", "B", 24)
    score_text = f"{last_score}"
    pdf.cell(0, 15, score_text, ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, "Security Score out of 100", ln=True, align="C")

    # Score interpretation
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    if last_score >= 90:
        status = "EXCELLENT"
        desc = "Your system has strong security measures in place."
    elif last_score >= 70:
        status = "GOOD"
        desc = "Your system is reasonably secure but has room for improvement."
    elif last_score >= 50:
        status = "FAIR"
        desc = "Several security issues need attention."
    else:
        status = "NEEDS ATTENTION"
        desc = "Immediate security improvements are recommended."

    pdf.cell(0, 10, f"Security Status: {status}", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 8, desc)

    # Date and time
    pdf.ln(5)
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 8, f"Assessment Date: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", ln=True)

    pdf.ln(10)
    # Executive Summary
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 8, "This report provides a comprehensive assessment of your system's security status. "
                        "It evaluates critical security components including firewall protection, network ports, "
                        "WiFi security, Windows updates, and antivirus protection. Each finding includes clear "
                        "recommendations for improvement.")
    pdf.ln(5)

    # Security Component Sections
    components = [
        {
            'title': 'Firewall Protection',
            'icon': '[FW]',
            'desc': 'Protects your computer from unauthorized network access',
            'findings': [f.replace('•', '-').replace('✓', '(PASS)') for f in last_findings if "firewall" in f.lower()] if last_findings else [],
            'default_msg': 'All firewalls are properly configured and active'
        },
        {
            'title': 'Network Security',
            'icon': '[NET]',
            'desc': 'Monitors open network ports and services',
            'findings': [f for f in last_findings if "port" in f.lower()] if last_findings else [],
            'default_msg': 'No suspicious network ports detected'
        },
        {
            'title': 'Antivirus Protection',
            'icon': '[AV]',
            'desc': 'Ensures your system is protected against malware',
            'findings': [f for f in last_findings if "defender" in f.lower() or "antivirus" in f.lower()] if last_findings else [],
            'default_msg': 'Antivirus protection is active and up-to-date'
        },
        {
            'title': 'System Updates',
            'icon': '[SYS]',
            'desc': 'Checks Windows system and security updates',
            'findings': [f for f in last_findings if "update" in f.lower()] if last_findings else [],
            'default_msg': 'System is up-to-date with all security patches'
        },
        {
            'title': 'WiFi Security',
            'icon': '[WIFI]',
            'desc': 'Analyzes wireless network security',
            'findings': [f for f in last_findings if "wifi" in f.lower()] if last_findings else [],
            'default_msg': 'WiFi networks are properly secured'
        }
    ]

    for comp in components:
        pdf.ln(8)
        # Component Header
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, f"{comp['icon']} {comp['title']}", ln=True)

        # Component Description
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(100, 100, 100)  # Gray color for description
        pdf.multi_cell(0, 6, comp['desc'])
        pdf.set_text_color(0, 0, 0)  # Reset to black

        # Findings
        pdf.set_font("Arial", "", 12)
        pdf.ln(2)
        if comp['findings']:
            for f in comp['findings']:
                # Clean up the text
                f = f.replace('✓', '(PASS)').replace('OFF', 'DISABLED').replace('ON', 'ENABLED')
                safe_text = f.encode('latin-1', 'replace').decode('latin-1')
                # Use different colors for different status
                if any(status in safe_text.upper() for status in ['PASS', 'SECURE', 'ENABLED']):
                    pdf.set_text_color(0, 128, 0)  # Green for good status
                elif any(status in safe_text.upper() for status in ['WARN', 'WEAK', 'DISABLED']):
                    pdf.set_text_color(255, 128, 0)  # Orange for warnings
                else:
                    pdf.set_text_color(0, 0, 0)  # Black for neutral
                pdf.multi_cell(0, 8, f"- {safe_text}")
                pdf.set_text_color(0, 0, 0)  # Reset color
        else:
            pdf.set_text_color(0, 128, 0)  # Green for good status
            pdf.multi_cell(0, 8, f"• {comp['default_msg']}")
            pdf.set_text_color(0, 0, 0)  # Reset color

    # WiFi Security Details
    if last_wifi_data:
        pdf.ln(10)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "[WIFI] Detailed WiFi Security Analysis", ln=True)
        pdf.ln(2)

        for wifi in last_wifi_data:
            ssid = wifi.get('SSID')
            label = wifi.get('strength_label', 'unknown')
            score_val = wifi.get('strength_score', None)
            reasons = wifi.get('strength_reasons', [])

            # Network Name
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 8, f"Network: {ssid}", ln=True)

            # Security Status
            pdf.set_font("Arial", "", 11)
            status_color = {
                'strong': (0, 128, 0),    # Green
                'moderate': (255, 128, 0), # Orange
                'weak': (255, 0, 0),      # Red
                'very weak': (255, 0, 0),  # Red
                'unknown': (128, 128, 128) # Gray
            }
            color = status_color.get(label, (0, 0, 0))
            pdf.set_text_color(*color)

            strength_text = label.replace('unknown', 'Not Analyzed').title()
            pdf.cell(0, 6, f"Security Level: {strength_text}", ln=True)
            pdf.set_text_color(0, 0, 0)  # Reset to black

            # Security Recommendations
            if label in ('weak', 'very weak', 'moderate'):
                pdf.ln(2)
                pdf.set_font("Arial", "B", 11)
                pdf.cell(0, 6, "Issues Found:", ln=True)
                pdf.set_font("Arial", "", 11)
                for r in reasons:
                    safe_r = r.replace("→", "to").encode('latin-1', 'replace').decode('latin-1')
                    pdf.multi_cell(0, 6, f"- {safe_r}")

                pdf.ln(2)
                pdf.set_font("Arial", "B", 11)
                pdf.cell(0, 6, "How to Fix:", ln=True)
                pdf.set_font("Arial", "", 11)
                if label in ("very weak", "weak"):
                    pdf.multi_cell(0, 6, "1. Change your WiFi password immediately\n"
                                       "2. Use a long passphrase (at least 12 characters)\n"
                                       "3. Include a mix of letters, numbers, and symbols\n"
                                       "4. Avoid common words or patterns\n"
                                       "5. Enable WPA3 encryption if your router supports it")
                elif label == "moderate":
                    pdf.multi_cell(0, 6, "1. Consider strengthening your password\n"
                                       "2. Use a longer passphrase\n"
                                       "3. Avoid using dictionary words\n"
                                       "4. Check if your router firmware is up to date")
            else:
                pdf.ln(2)
                pdf.set_font("Arial", "", 11)
                pdf.set_text_color(0, 128, 0)
                pdf.multi_cell(0, 6, "(PASS) This network meets security requirements")
                pdf.set_text_color(0, 0, 0)

            pdf.ln(5)

    # Action Items Section
    pdf.ln(10)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, ">>> Recommended Actions", ln=True)
    pdf.ln(2)

    if last_recommendations:
        # Group recommendations by priority
        critical = []
        important = []
        suggested = []

        for rec in last_recommendations:
            if any(kw in rec.lower() for kw in ['immediately', 'critical', 'risk', 'vulnerable']):
                critical.append(rec)
            elif any(kw in rec.lower() for kw in ['should', 'recommended', 'important']):
                important.append(rec)
            else:
                suggested.append(rec)

        # Print recommendations by priority
        if critical:
            pdf.set_font("Arial", "B", 12)
            pdf.set_text_color(255, 0, 0)
            pdf.cell(0, 8, "Critical - Fix These First:", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", 11)
            for rec in critical:
                safe_rec = rec.replace("→", "to").encode('latin-1', 'replace').decode('latin-1')
                pdf.multi_cell(0, 6, f"[!] {safe_rec}")
            pdf.ln(3)

        if important:
            pdf.set_font("Arial", "B", 12)
            pdf.set_text_color(255, 128, 0)
            pdf.cell(0, 8, "Important - Address These Soon:", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", 11)
            for rec in important:
                safe_rec = rec.replace("→", "to").encode('latin-1', 'replace').decode('latin-1')
                pdf.multi_cell(0, 6, f"[*] {safe_rec}")
            pdf.ln(3)

        if suggested:
            pdf.set_font("Arial", "B", 12)
            pdf.set_text_color(0, 128, 0)
            pdf.cell(0, 8, "Suggested Improvements:", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", 11)
            for rec in suggested:
                safe_rec = rec.replace("→", "to").encode('latin-1', 'replace').decode('latin-1')
                pdf.multi_cell(0, 6, f"[+] {safe_rec}")
    else:
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 8, "✓ No critical actions needed at this time", ln=True)
        pdf.set_text_color(0, 0, 0)

    # Footer
    pdf.ln(10)
    pdf.set_font("Arial", "I", 10)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 6, "This report was generated by the Cyber Hygiene Monitor Tool", ln=True, align="C")
    pdf.cell(0, 6, f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", ln=True, align="C")
    pdf.set_text_color(0, 0, 0)

    report_path = "cyber_hygiene_report.pdf"
    pdf.output(report_path)
    return send_file(report_path, as_attachment=True)

if __name__ == "__main__":
    # NOTE: for most accurate results (antivirus status, full net info) run as Administrator on Windows.
    app.run(debug=True)
