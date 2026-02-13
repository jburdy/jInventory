#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux System Inventory Script
Port of Linux-Inventory.sh using Python 3.14+

Generates 6 Markdown reports:
  1. hardware.md   - static hardware info
  2. software.md   - installed software & versions
  3. state.md      - live runtime state
  4. diskspace.md  - disk space usage by category
  5. filestats.md  - detailed extension breakdown for Other files
  6. catpaths.md   - primary storage paths per file category
"""

import concurrent.futures
import datetime
import json
import platform
import re
import shutil
import socket
import stat as stat_mod
import subprocess
import sys
from pathlib import Path

try:
    import psutil
except ImportError:
    print("[ERROR] psutil not installed. Run: pip install psutil")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
HOSTNAME = socket.gethostname()

HW_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-0-hardware.md"
SW_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-1-software.md"
ST_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-2-state.md"
DS_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-3-diskspace.md"
FS_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-4-filestats.md"
CP_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-5-catpaths.md"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def run_cmd(command: str, *, timeout: int = 30) -> str:
    """Run a shell command and return stdout."""
    try:
        r = subprocess.run(
            command, shell=True,
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def which(name: str) -> bool:
    return shutil.which(name) is not None


def format_bytes(n: int | float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _sanitize(text: str) -> str:
    """Strip ANSI escape codes and non-printable characters."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    return "".join(c for c in text if c.isprintable() or c in "\n\t")


def _read_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, PermissionError):
        return ""


def _dir_size_bytes(path: Path) -> int:
    """Get directory size using du -sb (fast C implementation)."""
    out = run_cmd(f"du -sb '{path}' 2>/dev/null")
    if out:
        try:
            return int(out.split()[0])
        except (ValueError, IndexError):
            pass
    return 0


def _get_real_mounts() -> list:
    """Return real (non-virtual) mount partitions."""
    skip_fs = {"tmpfs", "devtmpfs", "overlay", "efivarfs", "squashfs"}
    result = []
    for part in psutil.disk_partitions(all=False):
        if part.fstype in skip_fs:
            continue
        if "/run/credentials" in part.mountpoint:
            continue
        result.append(part)
    return result


# ---------------------------------------------------------------------------
# File-type categories (loaded from categories.json, shared across scripts)
# ---------------------------------------------------------------------------
def _load_categories() -> tuple[dict[str, set[str]], dict[str, str]]:
    """Load categories from categories.json next to this script."""
    cat_file = SCRIPT_DIR / "categories.json"
    raw: dict[str, list[str]] = json.loads(cat_file.read_text(encoding="utf-8"))
    categories = {cat: set(exts) for cat, exts in raw.items()}
    ext_to_cat = {ext: cat for cat, exts in categories.items() for ext in exts}
    return categories, ext_to_cat


_CATEGORIES, _EXT_TO_CAT = _load_categories()

# Type alias for _scan_mount return value
type ScanResult = tuple[
    dict[str, list[int]],              # cat_stats
    dict[str, list[int]],              # other_ext_stats
    dict[str, dict[str, list[int]]],   # cat_dir_stats {cat: {subdir: [n, bytes]}}
    int,                               # files_scanned
]


def _scan_mount(
    root: Path, max_files: int = 200_000,
) -> ScanResult:
    """Scan files under root (same device, no symlink follow).

    Uses a single lstat() per entry for performance.
    Returns (cat_stats, other_ext_stats, cat_dir_stats, files_scanned).
      - cat_stats:       {category: [count, total_bytes]}
      - other_ext_stats: {extension: [count, total_bytes]} for "Other" files
      - cat_dir_stats:   {category: {subdir_name: [count, total_bytes]}}
    """
    stats: dict[str, list[int]] = {}
    other_exts: dict[str, list[int]] = {}
    cat_dirs: dict[str, dict[str, list[int]]] = {}
    scanned = 0
    root_depth = len(root.parts)
    try:
        root_dev = root.stat().st_dev
    except OSError:
        return stats, other_exts, cat_dirs, scanned

    stack = [root]
    while stack and scanned < max_files:
        current = stack.pop()
        try:
            for entry in current.iterdir():
                if scanned >= max_files:
                    break
                try:
                    st = entry.lstat()
                    mode = st.st_mode
                    if stat_mod.S_ISLNK(mode):
                        continue
                    if stat_mod.S_ISDIR(mode):
                        if st.st_dev == root_dev:
                            stack.append(entry)
                    elif stat_mod.S_ISREG(mode):
                        ext = entry.suffix.lower()
                        cat = _EXT_TO_CAT.get(ext, "Other")
                        if cat in stats:
                            stats[cat][0] += 1
                            stats[cat][1] += st.st_size
                        else:
                            stats[cat] = [1, st.st_size]
                        # Track per-extension detail for Other files
                        if cat == "Other":
                            key = ext if ext else "(no ext)"
                            if key in other_exts:
                                other_exts[key][0] += 1
                                other_exts[key][1] += st.st_size
                            else:
                                other_exts[key] = [1, st.st_size]
                        # Track first-level subdir per category
                        eparts = entry.parts
                        if len(eparts) > root_depth + 1:
                            dkey = eparts[root_depth]
                        else:
                            dkey = "."
                        dirs = cat_dirs.get(cat)
                        if dirs is None:
                            cat_dirs[cat] = {dkey: [1, st.st_size]}
                        elif dkey in dirs:
                            dirs[dkey][0] += 1
                            dirs[dkey][1] += st.st_size
                        else:
                            dirs[dkey] = [1, st.st_size]
                        scanned += 1
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            continue

    return stats, other_exts, cat_dirs, scanned


# ============================================================
# 1. HARDWARE REPORT
# ============================================================
def generate_hardware() -> None:
    lines: list[str] = []
    w = lines.append

    w(f"# Hardware Inventory - {HOSTNAME}")
    w("")
    w(f"> Generated: {TIMESTAMP}")
    w("")

    # --- System ---
    w("## System")
    w("")
    w("| Property | Value |")
    w("|----------|-------|")
    w(f"| Hostname | {HOSTNAME} |")

    if which("hostnamectl"):
        hctl = _sanitize(run_cmd("hostnamectl"))
        for label, key in [
            ("Chassis", "Chassis"),
            ("Manufacturer", "Hardware Vendor"),
            ("Model", "Hardware Model"),
            ("Serial", "Hardware Serial"),
            ("Firmware Version", "Firmware Version"),
            ("Firmware Date", "Firmware Date"),
            ("Firmware Age", "Firmware Age"),
        ]:
            m = re.search(rf"{key}:\s*(.+)", hctl)
            w(f"| {label} | {m.group(1).strip() if m else 'N/A'} |")
    elif which("dmidecode"):
        w(f"| Manufacturer | {run_cmd('dmidecode -s system-manufacturer') or 'N/A'} |")
        w(f"| Product | {run_cmd('dmidecode -s system-product-name') or 'N/A'} |")
        w(f"| Serial | {run_cmd('dmidecode -s system-serial-number') or 'N/A'} |")
    w("")

    # --- CPU ---
    w("## CPU")
    w("")
    w("| Property | Value |")
    w("|----------|-------|")
    lscpu_out = run_cmd("lscpu")

    def _lscpu(key: str) -> str:
        m = re.search(rf"^{re.escape(key)}:\s*(.+)", lscpu_out, re.MULTILINE)
        return m.group(1).strip() if m else "N/A"

    w(f"| Model | {_lscpu('Model name')} |")
    w(f"| Architecture | {_lscpu('Architecture')} |")
    w(f"| Cores | {psutil.cpu_count(logical=False)} |")
    w(f"| Threads | {psutil.cpu_count(logical=True)} |")
    w(f"| Virtualization | {_lscpu('Virtualization')} |")
    w("")

    # --- RAM modules ---
    w("## Memory (hardware)")
    w("")
    mem = psutil.virtual_memory()
    w(f"- **Total installed**: {format_bytes(mem.total)}")
    w("")

    if which("dmidecode"):
        dmi = run_cmd("dmidecode -t memory")
        if dmi:
            w("| Slot | Size | Type | Speed |")
            w("|------|------|------|-------|")
            blocks = re.split(r"Memory Device\n", dmi)
            for block in blocks[1:]:
                slot = size = mtype = speed = ""
                for line in block.splitlines():
                    line = line.strip()
                    if line.startswith("Locator:") and "Bank" not in line:
                        slot = line.split(":", 1)[1].strip()
                    elif line.startswith("Size:"):
                        size = line.split(":", 1)[1].strip()
                    elif line.startswith("Type:") and "Detail" not in line and "Error" not in line:
                        mtype = line.split(":", 1)[1].strip()
                    elif line.startswith("Speed:") and "Configured" not in line:
                        speed = line.split(":", 1)[1].strip()
                if size and size != "No Module Installed":
                    w(f"| {slot} | {size} | {mtype} | {speed} |")
    w("")

    # --- Storage Devices ---
    w("## Storage Devices")
    w("")
    w("```")
    lsblk = run_cmd("lsblk -o NAME,SIZE,TYPE,FSTYPE,MODEL")
    if lsblk:
        for line in lsblk.splitlines():
            if "loop" not in line:
                w(_sanitize(line))
    else:
        w("(lsblk not available)")
    w("```")
    w("")

    # --- Disk Details (SMART) ---
    if which("smartctl"):
        w("## Disk Details (SMART)")
        w("")
        w("| Device | Model | Serial | Firmware | Capacity |")
        w("|--------|-------|--------|----------|----------|")
        scan = run_cmd("smartctl --scan")
        for line in scan.splitlines():
            dev = line.split()[0] if line.split() else ""
            if not dev:
                continue
            info = run_cmd(f"smartctl -i {dev}")
            if not info:
                continue

            def _sf(pattern: str) -> str:
                m = re.search(pattern, info)
                return m.group(1).strip() if m else "N/A"

            model = _sf(r"(?:Device Model|Model Number):\s*(.+)")
            serial = _sf(r"Serial Number:\s*(.+)")
            fw = _sf(r"Firmware Version:\s*(.+)")
            cap_m = re.search(r"(?:User Capacity|Total NVM Capacity).*\[(.+?)\]", info)
            cap = cap_m.group(1) if cap_m else "N/A"
            w(f"| {dev} | {model} | {serial} | {fw} | {cap} |")
        w("")
    else:
        w("> smartctl not available - disk details skipped")
        w("")

    # --- Network Interfaces ---
    w("## Network Interfaces (physical)")
    w("")
    w("| Interface | MAC | Driver |")
    w("|-----------|-----|--------|")
    net_dir = Path("/sys/class/net")
    if net_dir.exists():
        skip_prefixes = ("lo", "veth", "br-", "docker")
        for iface in sorted(net_dir.iterdir()):
            name = iface.name
            if any(name.startswith(p) for p in skip_prefixes):
                continue
            mac = _read_file(str(iface / "address")) or "N/A"
            driver = "N/A"
            driver_link = iface / "device" / "driver"
            try:
                if driver_link.exists():
                    driver = driver_link.resolve().name
            except OSError:
                pass
            w(f"| {name} | {mac} | {driver} |")
    w("")

    # --- PCI / USB ---
    w("## PCI Devices")
    w("")
    w("```")
    w(run_cmd("lspci") or "lspci not available")
    w("```")
    w("")
    w("## USB Devices")
    w("")
    w("```")
    w(run_cmd("lsusb") or "lsusb not available")
    w("```")
    w("")

    # --- Firmware ---
    if which("fwupdmgr"):
        w("## Firmware Inventory (fwupd)")
        w("")
        w("```")
        w(_sanitize(run_cmd("fwupdmgr get-devices", timeout=15)))
        w("```")
        w("")

    # --- Detailed Hardware ---
    if which("lshw"):
        w("## Detailed Hardware (lshw)")
        w("")
        w("```")
        w(run_cmd("lshw -short", timeout=30))
        w("```")
        w("")

    HW_FILE.write_text("\n".join(lines), encoding="utf-8")


# ============================================================
# 2. SOFTWARE REPORT
# ============================================================
def generate_software() -> None:
    lines: list[str] = []
    w = lines.append

    w(f"# Software Inventory - {HOSTNAME}")
    w("")
    w(f"> Generated: {TIMESTAMP}")
    w("")

    # --- OS ---
    w("## Operating System")
    w("")
    w("| Property | Value |")
    w("|----------|-------|")
    os_release = _read_file("/etc/os-release")
    m = re.search(r'PRETTY_NAME="(.+?)"', os_release)
    distro = m.group(1) if m else platform.platform()
    w(f"| Distribution | {distro} |")
    w(f"| Kernel | {platform.release()} |")
    w(f"| Architecture | {platform.machine()} |")
    w("")

    # --- Locale & Keymap ---
    if which("localectl"):
        w("## System Locale & Keymap")
        w("")
        w("```")
        w(run_cmd("localectl") or "(not available)")
        w("```")
        w("")

    # --- Software Versions ---
    w("## Software Versions")
    w("")
    w("| Software | Version |")
    w("|----------|---------|")

    version_checks = [
        ("Bash", "bash --version", r"(\d+\.\d+\.\d+)"),
        ("Python", "python3 --version", r"Python (.+)"),
        ("Node.js", "node --version", None),
        ("NPM", "npm --version", None),
        ("Go", "go version", r"(go\d+\.\d+\.\d+)"),
        ("Git", "git --version", r"(\d+\.\d+\.\d+)"),
        ("Docker", "docker --version", r"(\d+\.\d+\.\d+)"),
        ("Docker Compose", "docker compose version", r"v?(\d+\.\d+\.\d+)"),
        ("Nginx", "nginx -v 2>&1", r"nginx/(.+)"),
        ("PostgreSQL", "psql --version", r"(\d+\.\d+)"),
        ("MySQL", "mysql --version", r"(\d+\.\d+\.\d+)"),
        ("Redis", "redis-server --version", r"v=(\S+)"),
        ("Mosquitto", "mosquitto -h 2>&1", r"version (\S+)"),
        ("Fish", "fish --version", r"version (.+)"),
        ("Tmux", "tmux -V", r"tmux (.+)"),
    ]

    for name, cmd, pattern in version_checks:
        tool = cmd.split()[0]
        if not which(tool):
            continue
        out = run_cmd(cmd)
        if not out:
            continue
        if pattern:
            m = re.search(pattern, out)
            ver = m.group(1) if m else out.splitlines()[0]
        else:
            ver = out.splitlines()[0].strip()
        w(f"| {name} | {ver} |")
    w("")

    # --- Pacman Packages ---
    if which("pacman"):
        pkg_count = run_cmd("pacman -Q 2>/dev/null | wc -l") or "?"
        orphan_count = run_cmd("pacman -Qtdq 2>/dev/null | wc -l") or "0"
        w(f"## Installed Packages ({pkg_count} total, {orphan_count} orphans)")
        w("")
        w("### Explicitly Installed")
        w("")
        w("```")
        w(run_cmd("pacman -Qe", timeout=15))
        w("```")
        w("")
        w("### Recent Package Changes (last 30)")
        w("")
        w("```")
        w(run_cmd(
            r"tail -100 /var/log/pacman.log 2>/dev/null"
            r" | grep -E '\[ALPM\] (installed|upgraded|removed)' | tail -30"
        ))
        w("```")
        w("")

    # --- Top 20 Packages by Size ---
    if which("expac"):
        w("### Top 20 Packages by Size")
        w("")
        w("| Size | Package | Version |")
        w("|------|---------|---------|")
        out = run_cmd(r"expac -H M '%m\t%n\t%v' | sort -rn | head -20")
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                w(f"| {parts[0]} | {parts[1]} | {parts[2]} |")
        w("")

    # --- Enabled Services ---
    w("## Enabled Services")
    w("")
    w("```")
    w(run_cmd(
        "systemctl list-unit-files --type=service --state=enabled --no-pager",
        timeout=15,
    ))
    w("```")
    w("")

    # --- Scheduled Tasks ---
    w("## Scheduled Tasks")
    w("")
    w("### Crontab (root)")
    w("")
    w("```")
    w(run_cmd("crontab -l 2>/dev/null") or "(no crontab for root)")
    w("```")
    w("")
    w("### System Crontab")
    w("")
    w("```")
    w(_read_file("/etc/crontab") or "(empty)")
    w("```")
    w("")
    w("### Systemd Timers")
    w("")
    w("```")
    w(run_cmd("systemctl list-timers --all --no-pager", timeout=15))
    w("```")
    w("")

    # --- Docker ---
    if which("docker"):
        for section, cmd in [
            ("Docker Images", 'docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"'),
            ("Docker Volumes", "docker volume ls"),
            ("Docker Networks", "docker network ls"),
            ("Docker Compose Projects", "docker compose ls"),
        ]:
            w(f"## {section}")
            w("")
            w("```")
            w(run_cmd(cmd) or "(none)")
            w("```")
            w("")

    # --- Users ---
    w("## Users with Login Shell")
    w("")
    w("| User | UID | Shell |")
    w("|------|-----|-------|")
    passwd = _read_file("/etc/passwd")
    for line in passwd.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 7 and "nologin" not in parts[6] and "false" not in parts[6]:
            w(f"| {parts[0]} | {parts[2]} | {parts[6]} |")
    w("")

    # --- Listening Ports ---
    w("## Listening Ports")
    w("")
    w("```")
    w(run_cmd("ss -tulpn 2>/dev/null | grep LISTEN"))
    w("```")
    w("")

    # --- DNS ---
    w("## DNS Configuration")
    w("")
    w("```")
    resolv = _read_file("/etc/resolv.conf")
    for line in resolv.splitlines():
        if line.strip() and not line.startswith("#"):
            w(line)
    w("```")
    w("")

    SW_FILE.write_text("\n".join(lines), encoding="utf-8")


# ============================================================
# 3. STATE REPORT
# ============================================================
def generate_state() -> None:
    lines: list[str] = []
    w = lines.append

    w(f"# System State - {HOSTNAME}")
    w("")
    w(f"> Generated: {TIMESTAMP}")
    w("")

    # --- System Status ---
    w("## System Status")
    w("")
    w("| Property | Value |")
    w("|----------|-------|")

    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.datetime.now() - boot_time
    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, _ = divmod(remainder, 60)

    w(f"| Uptime | {days}d {hours}h {minutes}m |")
    w(f"| Last Boot | {boot_time.strftime('%Y-%m-%d %H:%M:%S')} |")
    w(f"| Current Users | {len(psutil.users())} |")
    load = psutil.getloadavg()
    w(f"| Load Average | {load[0]:.2f} {load[1]:.2f} {load[2]:.2f} |")

    if which("timedatectl"):
        tctl = run_cmd("timedatectl")
        m_sync = re.search(r"synchronized:\s*(.+)", tctl)
        m_svc = re.search(r"NTP service:\s*(.+)", tctl)
        w(f"| NTP Synchronized | {m_sync.group(1).strip() if m_sync else 'N/A'} |")
        w(f"| NTP Service | {m_svc.group(1).strip() if m_svc else 'N/A'} |")
    w("")

    # --- CPU Usage ---
    w("## CPU Usage")
    w("")
    cpu_pct = psutil.cpu_percent(interval=1)
    w(f"- **CPU used**: {cpu_pct}%")
    w("")

    # --- Memory Usage ---
    w("## Memory Usage")
    w("")
    w("```")
    w(run_cmd("free -h"))
    w("```")
    w("")
    vmem = psutil.virtual_memory()
    w(f"- **RAM used**: {vmem.percent}%")
    w("")

    # --- Temperatures ---
    if which("sensors"):
        w("## Temperatures & Fans")
        w("")
        w("```")
        w(_sanitize(run_cmd("sensors")))
        w("```")
        w("")

    # --- Disk Usage ---
    w("## Disk Usage")
    w("")
    w("| Filesystem | Size | Used | Avail | Use% | Mount |")
    w("|------------|------|------|-------|------|-------|")
    skip_words = ("tmpfs", "devtmpfs", "overlay", "efivar", "/run/credentials")
    df_out = run_cmd("df -h --output=source,size,used,avail,pcent,target")
    if df_out:
        for line in df_out.splitlines()[1:]:
            if any(s in line for s in skip_words):
                continue
            parts = line.split()
            if len(parts) >= 6 and parts[0] != "none":
                w(f"| {parts[0]} | {parts[1]} | {parts[2]} | {parts[3]} | {parts[4]} | {parts[5]} |")
    w("")

    w("### Top 10 Directories by Size")
    w("")
    w("```")
    w(run_cmd("du -h / --max-depth=1 2>/dev/null | sort -rh | head -10", timeout=60))
    w("```")
    w("")

    # --- Disk Health (SMART) ---
    if which("smartctl"):
        w("## Disk Health")
        w("")
        w("| Device | Model | Health | Temp | Power-On | Wear |")
        w("|--------|-------|--------|------|----------|------|")
        scan = run_cmd("smartctl --scan")
        for line in scan.splitlines():
            dev_parts = line.split("#")[0].strip().split()
            if not dev_parts:
                continue
            dev = dev_parts[0]
            opts = " ".join(dev_parts[1:])

            health_out = run_cmd(f"smartctl -H {opts} {dev}")
            health = "N/A"
            if "PASSED" in health_out:
                health = "PASSED"
            elif "FAILED" in health_out:
                health = "FAILED"

            info_out = run_cmd(f"smartctl -i {opts} {dev}")
            m_model = re.search(r"(?:Device Model|Model Number):\s*(.+)", info_out)
            model = m_model.group(1).strip() if m_model else "N/A"

            temp = hours = wear = "-"
            if "nvme" in dev or "nvme" in opts:
                if which("nvme"):
                    nvme_dev = re.sub(r"n1$", "", dev)
                    smart = run_cmd(f"nvme smart-log {nvme_dev}")
                    m_t = re.search(r"^temperature\s*:\s*(.+)", smart, re.MULTILINE)
                    m_h = re.search(r"^power_on_hours\s*:\s*(\S+)", smart, re.MULTILINE)
                    m_w = re.search(r"^percentage_used\s*:\s*(\S+)", smart, re.MULTILINE)
                    if m_t:
                        temp = m_t.group(1).strip()
                    if m_h:
                        hours = m_h.group(1).strip()
                    if m_w:
                        wear = m_w.group(1).strip()
                    m_spare = re.search(r"^available_spare\s*:\s*(\S+)", smart, re.MULTILINE)
                    if m_spare and wear != "-":
                        wear += f" (spare: {m_spare.group(1).strip()})"
            else:
                attr = run_cmd(f"smartctl -A {opts} {dev}")
                m_t = re.search(
                    r"(?:Temperature_Celsius|Airflow_Temperature)\s+\S+\s+\S+\s+\S+\s+"
                    r"\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)", attr,
                )
                m_h = re.search(
                    r"Power_On_Hours\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)", attr,
                )
                if m_t:
                    temp = f"{m_t.group(1)} C"
                if m_h:
                    hours = m_h.group(1)

            w(f"| {dev} | {model} | {health} | {temp} | {hours} h | {wear} |")
        w("")
    else:
        w("> smartctl not available - disk health skipped")
        w("")

    # --- Top Processes ---
    w("## Top Processes by CPU")
    w("")
    w("```")
    w(run_cmd("ps aux --sort=-%cpu | head -16"))
    w("```")
    w("")
    w("## Top Processes by Memory")
    w("")
    w("```")
    w(run_cmd("ps aux --sort=-%mem | head -16"))
    w("```")
    w("")

    # --- Running / Failed Services ---
    w("## Running Services")
    w("")
    w("```")
    w(_sanitize(run_cmd(
        "systemctl list-units --type=service --state=running --no-pager",
        timeout=15,
    )))
    w("```")
    w("")
    w("## Failed Services")
    w("")
    w("```")
    w(_sanitize(run_cmd(
        "systemctl list-units --type=service --state=failed --no-pager",
        timeout=15,
    )))
    w("```")
    w("")

    # --- Docker Containers ---
    if which("docker"):
        w("## Docker Containers")
        w("")
        w("### Running")
        w("")
        w("```")
        w(run_cmd(
            'docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"',
        ) or "(docker not running)")
        w("```")
        w("")
        w("### All (including stopped)")
        w("")
        w("```")
        w(run_cmd(
            'docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"',
        ) or "(docker not running)")
        w("```")
        w("")

    # --- Pending Updates ---
    if which("checkupdates"):
        w("## Pending Updates")
        w("")
        updates = run_cmd("checkupdates", timeout=60)
        if updates:
            count = len(updates.splitlines())
            w(f"**{count} updates available:**")
            w("")
            w("```")
            w(updates)
            w("```")
        else:
            w("System is up to date.")
        w("")

    # --- Active Connections ---
    w("## Active Network Connections")
    w("")
    w("```")
    w(run_cmd("ss -tunap 2>/dev/null | head -30"))
    w("```")
    w("")

    # --- Network IPs ---
    w("## Network Addresses")
    w("")
    w("```")
    w(run_cmd("ip -br addr show 2>/dev/null | grep -v veth | grep -v 'br-' | grep -v docker"))
    w("```")
    w("")

    # --- Recent Logs ---
    w("## Recent System Logs (last 30)")
    w("")
    w("```")
    w(run_cmd("journalctl -n 30 --no-pager", timeout=15))
    w("```")
    w("")

    ST_FILE.write_text("\n".join(lines), encoding="utf-8")


# ============================================================
# 4. DISK SPACE REPORT
# ============================================================
def generate_disk_space() -> dict[str, ScanResult]:
    lines: list[str] = []
    w = lines.append

    w(f"# Disk Space Usage Analysis - {HOSTNAME}")
    w("")
    w(f"> Generated: {TIMESTAMP}")
    w("")

    # --- Overall Disk Usage Summary ---
    w("## Overall Disk Usage Summary")
    w("")
    w("| Filesystem | Size | Used | Avail | Use% | Mount |")
    w("|------------|------|------|-------|------|-------|")

    mounts = _get_real_mounts()
    total_used = 0
    for part in mounts:
        try:
            usage = psutil.disk_usage(part.mountpoint)
            total_used += usage.used
            w(
                f"| {part.device} | {format_bytes(usage.total)} | "
                f"{format_bytes(usage.used)} | {format_bytes(usage.free)} | "
                f"{usage.percent:.0f}% | {part.mountpoint} |"
            )
        except (PermissionError, OSError):
            pass
    w("")
    w(f"**Total system storage used**: {format_bytes(total_used)}")
    w("")

    # --- Scan all mounts in parallel ---
    print("  Scanning file categories (parallel)...")
    mount_paths = [part.mountpoint for part in mounts]
    drive_results: dict[str, ScanResult] = {}

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(4, max(1, len(mount_paths)))
    ) as pool:
        futures = {
            pool.submit(_scan_mount, Path(m)): m for m in mount_paths
        }
        for future in concurrent.futures.as_completed(futures, timeout=600):
            mount = futures[future]
            try:
                result = future.result(timeout=300)
                drive_results[mount] = result
                _, _, _, scanned = result
                print(f"    {mount}: {scanned:,} files scanned")
            except Exception as exc:
                print(f"    {mount}: scan failed ({exc})")
                drive_results[mount] = ({}, {}, {}, 0)

    # --- File Categories (all mounts combined) ---
    w("## File Categories (all mounts)")
    w("")

    global_stats: dict[str, list[int]] = {}
    global_scanned = 0
    for stats, _other_exts, _cat_dirs, scanned in drive_results.values():
        global_scanned += scanned
        for cat, (cnt, tot) in stats.items():
            if cat in global_stats:
                global_stats[cat][0] += cnt
                global_stats[cat][1] += tot
            else:
                global_stats[cat] = [cnt, tot]

    if global_stats:
        truncated = " (truncated on some mounts)" if global_scanned >= 200_000 else ""
        w(f"*Scanned {global_scanned:,} files{truncated}*")
        w("")
        by_size = sorted(global_stats.items(), key=lambda x: x[1][1], reverse=True)
        w("| Category | Count | Total Size |")
        w("|----------|-------|------------|")
        for cat, (count, total_size) in by_size:
            w(f"| {cat} | {count:,} | {format_bytes(total_size)} |")
        w("")
    else:
        w("(no files found)")
        w("")

    # --- File Categories per Mount ---
    w("## File Categories per Mount")
    w("")

    for mount in mount_paths:
        w(f"### Mount {mount}")
        w("")
        stats, _oext, _cdirs, scanned = drive_results.get(mount, ({}, {}, {}, 0))
        if not stats:
            w("(no files found or access denied)")
            w("")
            continue
        truncated = " (truncated)" if scanned >= 200_000 else ""
        w(f"*Scanned {scanned:,} files{truncated}*")
        w("")
        by_size = sorted(stats.items(), key=lambda x: x[1][1], reverse=True)
        w("| Category | Count | Total Size |")
        w("|----------|-------|------------|")
        for cat, (count, total_size) in by_size:
            w(f"| {cat} | {count:,} | {format_bytes(total_size)} |")
        w("")

    # --- User Directory Analysis ---
    w("## User Directory Analysis")
    w("")

    home_dir = Path("/home")
    if home_dir.exists():
        for user_home in sorted(home_dir.iterdir()):
            if not user_home.is_dir():
                continue
            username = user_home.name

            w(f"### User: {username}")
            w("")

            dirs_to_analyze = [
                "Desktop", "Documents", "Downloads", "Pictures",
                "Videos", "Music", ".local", ".cache",
            ]
            user_total = 0
            for dir_name in dirs_to_analyze:
                dir_path = user_home / dir_name
                if dir_path.is_dir():
                    dir_size = _dir_size_bytes(dir_path)
                    if dir_size > 0:
                        user_total += dir_size
                        w(f"- **{dir_name}**: {format_bytes(dir_size)}")

            if user_total > 0:
                w(f"**Total for {username}**: {format_bytes(user_total)}")
            else:
                w(f"**Total for {username}**: No accessible data")
            w("")

            # Detailed category analysis for important directories
            for dir_name in ("Documents", "Downloads", "Desktop"):
                dir_path = user_home / dir_name
                if not dir_path.is_dir():
                    continue
                dir_size = _dir_size_bytes(dir_path)
                if dir_size < 100 * 1024 * 1024:
                    continue

                w(f"#### Category Analysis for {dir_name}")
                w("")

                cat_stats: dict[str, int] = {}
                try:
                    for f in dir_path.rglob("*"):
                        try:
                            st = f.lstat()
                            if not stat_mod.S_ISREG(st.st_mode):
                                continue
                            if st.st_size < 50 * 1024 * 1024:
                                continue
                            ext = f.suffix.lower()
                            cat = _EXT_TO_CAT.get(ext, "Other")
                            cat_stats[cat] = cat_stats.get(cat, 0) + st.st_size
                        except (OSError, PermissionError):
                            continue
                except (OSError, PermissionError):
                    pass

                grand = sum(cat_stats.values())
                if grand > 0:
                    w("| Category | Size | Percentage |")
                    w("|----------|------|------------|")
                    for cat, tot in sorted(cat_stats.items(), key=lambda x: x[1], reverse=True):
                        pct = tot * 100 // grand
                        w(f"| {cat} | {format_bytes(tot)} | {pct}% |")
                    w("")
                else:
                    w("No large files found for detailed analysis.")
                    w("")

    # --- System Directory Analysis ---
    w("## System Directory Analysis")
    w("")

    for dir_str in ("/usr", "/opt", "/var", "/tmp", "/srv"):
        dp = Path(dir_str)
        if dp.is_dir():
            size = _dir_size_bytes(dp)
            if size > 0:
                w(f"- **{dir_str}**: {format_bytes(size)}")
    w("")

    if Path("/opt").is_dir():
        w("### Applications in /opt")
        w("")
        w("| Directory | Size |")
        w("|-----------|------|")
        try:
            for app_dir in sorted(Path("/opt").iterdir()):
                if not app_dir.is_dir():
                    continue
                app_size = _dir_size_bytes(app_dir)
                if app_size > 50 * 1024 * 1024:
                    w(f"| {app_dir.name} | {format_bytes(app_size)} |")
        except (OSError, PermissionError):
            pass
        w("")

    # --- Games Directory Analysis ---
    w("## Games Directory Analysis")
    w("")

    found_games = False
    home_games = Path("/home")
    if home_games.exists():
        for user_home in sorted(home_games.iterdir()):
            if not user_home.is_dir():
                continue
            for steam_candidate in [
                user_home / ".steam" / "steam" / "steamapps",
                user_home / ".local" / "share" / "Steam" / "steamapps",
            ]:
                if not steam_candidate.is_dir():
                    continue
                found_games = True
                w(f"### Steam games for {user_home.name}")
                w("")
                w("| Game Directory | Size |")
                w("|----------------|------|")
                common = steam_candidate / "common"
                if common.is_dir():
                    try:
                        for game_dir in sorted(common.iterdir()):
                            if not game_dir.is_dir():
                                continue
                            gsize = _dir_size_bytes(game_dir)
                            if gsize > 100 * 1024 * 1024:
                                w(f"| {game_dir.name} | {format_bytes(gsize)} |")
                    except (OSError, PermissionError):
                        pass
                w("")

    if not found_games:
        w("No common game directories found (Steam, Lutris, etc.).")
        w("")

    # --- Large Files Summary ---
    w("## Large Files Summary")
    w("")
    w("Searching for files larger than 500MB in user directories and /opt...")
    w("")

    large_out = run_cmd(
        "find /home /opt /usr -type f -size +500M -printf '%s\\t%p\\n' 2>/dev/null"
        " | sort -rn | head -50",
        timeout=120,
    )

    if large_out:
        w("| File Path | Size |")
        w("|-----------|------|")
        for line in large_out.splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2:
                try:
                    size = int(parts[0])
                    path_str = parts[1]
                    if len(path_str) > 80:
                        path_str = "..." + path_str[-77:]
                    w(f"| {path_str} | {format_bytes(size)} |")
                except ValueError:
                    continue
    else:
        w("No files larger than 500MB found in the searched directories.")
    w("")

    # --- Package Size Analysis ---
    if which("expac"):
        w("## Package Size Analysis")
        w("")
        w("### Top 30 Packages by Size")
        w("")
        w("| Size | Package | Version |")
        w("|------|---------|---------|")
        out = run_cmd(r"expac -H M '%m\t%n\t%v' | sort -rn | head -30")
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                w(f"| {parts[0]} | {parts[1]} | {parts[2]} |")
        w("")

        w("### Total Size by Category")
        w("")

        raw = run_cmd(r"expac '%m\t%n'")
        dev_total = games_total = media_total = system_total = 0
        dev_re = re.compile(r"(gcc|python|node|java|git|docker|vim|emacs)")
        games_re = re.compile(r"(steam|lutris|wine)")
        media_re = re.compile(r"(vlc|mpv|ffmpeg|gimp|inkscape)")

        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) != 2:
                continue
            try:
                size = int(parts[0])
            except ValueError:
                continue
            name = parts[1]
            if dev_re.search(name):
                dev_total += size
            elif games_re.search(name):
                games_total += size
            elif media_re.search(name):
                media_total += size
            else:
                system_total += size

        w("| Category | Estimated Size |")
        w("|----------|----------------|")
        if dev_total:
            w(f"| Development | {format_bytes(dev_total)} |")
        if games_total:
            w(f"| Games | {format_bytes(games_total)} |")
        if media_total:
            w(f"| Media | {format_bytes(media_total)} |")
        if system_total:
            w(f"| System | {format_bytes(system_total)} |")
        w("")

    DS_FILE.write_text("\n".join(lines), encoding="utf-8")
    return drive_results


# ============================================================
# 5. FILE STATS REPORT (Other extensions breakdown)
# ============================================================
def generate_filestats(
    drive_results: dict[str, ScanResult],
) -> None:
    """Generate a report breaking down Other files by extension."""
    lines: list[str] = []
    w = lines.append

    w(f"# File Extension Statistics (Other) - {HOSTNAME}")
    w("")
    w(f"> Generated: {TIMESTAMP}")
    w("")
    w("This report lists file extensions in the **Other** category that are significant")
    w("(>= 10 MB total or >= 1000 files). Use it to identify candidates for new categories.")
    w("")

    # --- Global Other extensions (all mounts combined) ---
    global_other: dict[str, list[int]] = {}
    global_other_count = 0
    global_other_size = 0

    for _stats, other_exts, _cat_dirs, _scanned in drive_results.values():
        for ext, (cnt, tot) in other_exts.items():
            if ext in global_other:
                global_other[ext][0] += cnt
                global_other[ext][1] += tot
            else:
                global_other[ext] = [cnt, tot]
            global_other_count += cnt
            global_other_size += tot

    w("## Global Other Extensions (all mounts)")
    w("")
    w(f"*{global_other_count:,} files, {len(global_other):,} distinct extensions, "
      f"{format_bytes(global_other_size)} total*")
    w("")

    MIN_SIZE = 10 * 1024 * 1024   # 10 MB
    MIN_COUNT = 1000

    significant = {
        ext: v for ext, v in global_other.items()
        if v[1] >= MIN_SIZE or v[0] >= MIN_COUNT
    }

    if significant:
        by_size = sorted(significant.items(), key=lambda x: x[1][1], reverse=True)
        w(f"*Showing {len(significant)} significant extensions "
          f"(>= 10 MB or >= 1000 files) out of {len(global_other):,} total*")
        w("")
        w("| Extension | Count | Total Size |")
        w("|-----------|-------|------------|")
        for ext, (count, total_size) in by_size:
            w(f"| {ext} | {count:,} | {format_bytes(total_size)} |")
        w("")
    else:
        w("(no Other files found)")
        w("")

    # --- Other extensions per mount ---
    w("## Other Extensions per Mount")
    w("")

    for mount, (_stats, other_exts, _cat_dirs, _scanned) in drive_results.items():
        w(f"### Mount {mount}")
        w("")
        if not other_exts:
            w("(no Other files)")
            w("")
            continue

        mount_count = sum(v[0] for v in other_exts.values())
        mount_size = sum(v[1] for v in other_exts.values())
        w(f"*{mount_count:,} files, {len(other_exts):,} extensions, "
          f"{format_bytes(mount_size)} total*")
        w("")

        sig = {
            ext: v for ext, v in other_exts.items()
            if v[1] >= MIN_SIZE or v[0] >= MIN_COUNT
        }
        if sig:
            by_size = sorted(sig.items(), key=lambda x: x[1][1], reverse=True)
            w("| Extension | Count | Total Size |")
            w("|-----------|-------|------------|")
            for ext, (count, total_size) in by_size:
                w(f"| {ext} | {count:,} | {format_bytes(total_size)} |")
        else:
            w("(no extension reaches threshold)")
        w("")

    FS_FILE.write_text("\n".join(lines), encoding="utf-8")


# ============================================================
# 6. CATEGORY PATHS REPORT (where each category lives)
# ============================================================
def generate_category_paths(
    drive_results: dict[str, ScanResult],
) -> None:
    """Generate a report showing primary storage paths for each category."""
    lines: list[str] = []
    w = lines.append

    w(f"# Category Locations - {HOSTNAME}")
    w("")
    w(f"> Generated: {TIMESTAMP}")
    w("")
    w("Primary storage locations for each file category.")
    w("Use this to quickly navigate to where specific file types are stored.")
    w("")

    # Collect all (mount, subdir, count, size) per category
    cat_locations: dict[str, list[tuple[str, str, int, int]]] = {}
    for mount, (_stats, _other_exts, cat_dirs, _scanned) in drive_results.items():
        for cat, dirs in cat_dirs.items():
            if cat == "Other":
                continue
            for subdir, (cnt, size) in dirs.items():
                cat_locations.setdefault(cat, []).append(
                    (mount, subdir, cnt, size)
                )

    # Compute global total per category for sorting
    cat_totals: dict[str, int] = {}
    for cat, locs in cat_locations.items():
        cat_totals[cat] = sum(size for _, _, _, size in locs)

    sorted_cats = sorted(cat_totals.items(), key=lambda x: x[1], reverse=True)

    MIN_CAT_SIZE = 10 * 1024 * 1024  # 10 MB

    # --- Quick reference table ---
    w("## Quick Reference")
    w("")
    w("| Category | Total Size | Primary Location | Location Size |")
    w("|----------|------------|------------------|---------------|")

    for cat, total in sorted_cats:
        if total < MIN_CAT_SIZE:
            continue
        best = max(cat_locations[cat], key=lambda x: x[3])
        mount, subdir, _cnt, size = best
        full_path = f"{mount.rstrip('/')}/{subdir}" if subdir != "." else mount
        w(f"| {cat} | {format_bytes(total)} | `{full_path}` | {format_bytes(size)} |")
    w("")

    # --- Detailed view per category ---
    w("## Detailed Paths per Category")
    w("")

    for cat, total in sorted_cats:
        if total < MIN_CAT_SIZE:
            continue

        w(f"### {cat} ({format_bytes(total)})")
        w("")

        # Group by mount, then show top subdirs
        mount_data: dict[str, list[tuple[str, int, int]]] = {}
        for mount, subdir, cnt, size in cat_locations[cat]:
            mount_data.setdefault(mount, []).append((subdir, cnt, size))

        # Sort mounts by total size descending
        mount_totals = [
            (m, sum(s for _, _, s in dirs))
            for m, dirs in mount_data.items()
        ]
        mount_totals.sort(key=lambda x: x[1], reverse=True)

        w("| Path | Files | Size |")
        w("|------|-------|------|")

        for mount, _mt in mount_totals:
            dirs = mount_data[mount]
            dirs.sort(key=lambda x: x[2], reverse=True)
            for subdir, cnt, size in dirs[:5]:
                if size < 1024 * 1024:  # skip < 1 MB
                    continue
                full_path = (
                    f"{mount.rstrip('/')}/{subdir}"
                    if subdir != "." else mount
                )
                w(f"| `{full_path}` | {cnt:,} | {format_bytes(size)} |")
        w("")

    CP_FILE.write_text("\n".join(lines), encoding="utf-8")


# ============================================================
# Main
# ============================================================
def main() -> None:
    print("Generating Linux system inventory...")
    print()

    generate_state()
    print(f"  [OK] {ST_FILE}")

    generate_hardware()
    print(f"  [OK] {HW_FILE}")

    generate_software()
    print(f"  [OK] {SW_FILE}")

    scan_results = generate_disk_space()
    print(f"  [OK] {DS_FILE}")

    generate_filestats(scan_results)
    print(f"  [OK] {FS_FILE}")

    generate_category_paths(scan_results)
    print(f"  [OK] {CP_FILE}")

    print()
    print("Done. 6 files generated:")
    for label, path in [
        ("Hardware", HW_FILE),
        ("Software", SW_FILE),
        ("State", ST_FILE),
        ("Disk Space", DS_FILE),
        ("File Stats", FS_FILE),
        ("Cat Paths", CP_FILE),
    ]:
        size = format_bytes(path.stat().st_size) if path.exists() else "?"
        print(f"  {label:10s}: {path} ({size})")


if __name__ == "__main__":
    main()
