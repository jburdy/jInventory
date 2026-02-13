# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
Windows 11 System Inventory Script
Port of Linux-Inventory.sh for Windows 11 using Python 3.14+

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
import winreg
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
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
def run_ps(command: str, *, timeout: int = 30) -> str:
    """Run a PowerShell command and return stdout."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def run_cmd(command: str, *, timeout: int = 30) -> str:
    """Run a CMD command and return stdout."""
    try:
        r = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            shell=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        # Try UTF-8 first, fallback to system encoding, strip null bytes
        try:
            out = r.stdout.decode("utf-8")
        except UnicodeDecodeError:
            out = r.stdout.decode("cp1252", errors="replace")
        return out.replace("\x00", "").strip()
    except Exception:
        return ""


def ps_json(command: str) -> list[dict]:
    """Run a PowerShell command that outputs JSON, return parsed list."""
    raw = run_ps(f"{command} | ConvertTo-Json -Compress")
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return [data]
        return data
    except (json.JSONDecodeError, TypeError):
        return []


def which(name: str) -> bool:
    """Check if a command is available on PATH."""
    return shutil.which(name) is not None


def get_version(cmd: str) -> str:
    """Run a command and return its first line of output."""
    out = run_cmd(cmd)
    if out:
        return out.splitlines()[0].strip()
    return "N/A"


def format_bytes(n: int | float) -> str:
    """Format bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# -- File-type categories (loaded from categories.json, shared across scripts) --
def _load_categories() -> tuple[dict[str, set[str]], dict[str, str]]:
    """Load categories from categories.json next to this script."""
    cat_file = SCRIPT_DIR / "categories.json"
    raw: dict[str, list[str]] = json.loads(cat_file.read_text(encoding="utf-8"))
    categories = {cat: set(exts) for cat, exts in raw.items()}
    ext_to_cat = {ext: cat for cat, exts in categories.items() for ext in exts}
    return categories, ext_to_cat


_CATEGORIES, _EXT_TO_CAT = _load_categories()


# Type alias for scan return value (matches Linux-Inventory.py)
type ScanResult = tuple[
    dict[str, list[int]],              # cat_stats
    dict[str, list[int]],              # other_ext_stats
    dict[str, dict[str, list[int]]],   # cat_dir_stats {cat: {subdir: [n, bytes]}}
    int,                               # files_scanned
]


def _scan_volume(root: Path, max_files: int = 200_000) -> ScanResult:
    """Scan files under *root* (no symlink follow).

    Uses lstat() per entry for performance.
    Returns (cat_stats, other_ext_stats, cat_dir_stats, files_scanned).
    """
    stats: dict[str, list[int]] = {}
    other_exts: dict[str, list[int]] = {}
    cat_dirs: dict[str, dict[str, list[int]]] = {}
    scanned = 0
    root_depth = len(root.parts)

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
# 1. HARDWARE REPORT (static)
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

    sys_info = ps_json("Get-CimInstance Win32_ComputerSystem")
    bios_info = ps_json("Get-CimInstance Win32_BIOS")

    if sys_info:
        s = sys_info[0]
        w(f"| Hostname | {HOSTNAME} |")
        w(f"| Manufacturer | {s.get('Manufacturer', 'N/A')} |")
        w(f"| Model | {s.get('Model', 'N/A')} |")
        w(f"| System Type | {s.get('SystemType', 'N/A')} |")
        w(f"| Domain | {s.get('Domain', 'N/A')} |")
    else:
        w(f"| Hostname | {HOSTNAME} |")

    if bios_info:
        b = bios_info[0]
        w(f"| BIOS Manufacturer | {b.get('Manufacturer', 'N/A')} |")
        w(f"| BIOS Version | {b.get('SMBIOSBIOSVersion', 'N/A')} |")
        w(f"| Serial Number | {b.get('SerialNumber', 'N/A')} |")
        release = b.get("ReleaseDate", "")
        if release:
            # PowerShell CIM dates come as "/Date(...)/" format
            m = re.search(r"/Date\((\d+)\)", str(release))
            if m:
                ts = int(m.group(1)) / 1000
                release = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
            w(f"| BIOS Date | {release} |")

    w("")

    # --- CPU ---
    w("## CPU")
    w("")
    w("| Property | Value |")
    w("|----------|-------|")

    cpu_info = ps_json("Get-CimInstance Win32_Processor")
    if cpu_info:
        c = cpu_info[0]
        w(f"| Model | {c.get('Name', 'N/A')} |")
        w(f"| Architecture | {platform.machine()} |")
        w(f"| Cores | {psutil.cpu_count(logical=False)} |")
        w(f"| Threads | {psutil.cpu_count(logical=True)} |")
        w(f"| Max Clock | {c.get('MaxClockSpeed', 'N/A')} MHz |")
        w(f"| L2 Cache | {format_bytes(c.get('L2CacheSize', 0) * 1024)} |")
        w(f"| L3 Cache | {format_bytes(c.get('L3CacheSize', 0) * 1024)} |")
        virt = "Yes" if c.get("VirtualizationFirmwareEnabled") else "No"
        w(f"| Virtualization | {virt} |")
    else:
        w(f"| Model | {platform.processor()} |")
        w(f"| Cores | {psutil.cpu_count(logical=False)} |")
        w(f"| Threads | {psutil.cpu_count(logical=True)} |")
    w("")

    # --- RAM modules ---
    w("## Memory (hardware)")
    w("")
    mem = psutil.virtual_memory()
    w(f"- **Total installed**: {format_bytes(mem.total)}")
    w("")

    ram_modules = ps_json("Get-CimInstance Win32_PhysicalMemory")
    if ram_modules:
        w("| Slot | Size | Type | Speed |")
        w("|------|------|------|-------|")
        mem_types = {
            0: "Unknown",
            20: "DDR",
            21: "DDR2",
            22: "DDR2 FB-DIMM",
            24: "DDR3",
            26: "DDR4",
            30: "LPDDR4",
            34: "DDR5",
            35: "LPDDR5",
        }
        for m in ram_modules:
            slot = m.get("DeviceLocator", "N/A")
            size = format_bytes(m.get("Capacity", 0))
            mtype = mem_types.get(m.get("SMBIOSMemoryType", 0), "Unknown")
            speed = f"{m.get('Speed', 'N/A')} MHz"
            w(f"| {slot} | {size} | {mtype} | {speed} |")
    w("")

    # --- Storage Devices ---
    w("## Storage Devices")
    w("")
    w("```")
    disks = ps_json(
        "Get-CimInstance Win32_DiskDrive | "
        "Select-Object DeviceID, Model, Size, MediaType, InterfaceType"
    )
    if disks:
        w(f"{'Device':<20} {'Model':<40} {'Size':>12} {'Type':<12} {'Interface'}")
        for d in disks:
            dev = d.get("DeviceID", "N/A")
            model = (d.get("Model") or "N/A")[:38]
            size = format_bytes(d.get("Size", 0))
            mtype = d.get("MediaType", "N/A") or "N/A"
            iface = d.get("InterfaceType", "N/A") or "N/A"
            w(f"{dev:<20} {model:<40} {size:>12} {mtype:<12} {iface}")
    else:
        w("(no disk information available)")
    w("```")
    w("")

    # --- Disk Partitions ---
    w("## Disk Partitions")
    w("")
    w("| Drive | Label | FS Type | Total | Used | Free |")
    w("|-------|-------|---------|-------|------|------|")
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            label_info = run_ps(
                f"(Get-Volume -DriveLetter '{part.mountpoint[0]}' -ErrorAction SilentlyContinue).FileSystemLabel"
            )
            label = label_info if label_info else "-"
            w(
                f"| {part.mountpoint} | {label} | {part.fstype} | "
                f"{format_bytes(usage.total)} | {format_bytes(usage.used)} | {format_bytes(usage.free)} |"
            )
        except (PermissionError, OSError):
            w(f"| {part.mountpoint} | - | {part.fstype} | N/A | N/A | N/A |")
    w("")

    # --- Network Interfaces ---
    w("## Network Interfaces")
    w("")
    w("| Interface | MAC | Status | Speed |")
    w("|-----------|-----|--------|-------|")

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for iface_name, iface_stats in sorted(stats.items()):
        if iface_name.startswith("Loopback"):
            continue
        mac = "N/A"
        if iface_name in addrs:
            for addr in addrs[iface_name]:
                if addr.family == psutil.AF_LINK:
                    mac = addr.address
                    break
        status = "Up" if iface_stats.isup else "Down"
        speed = f"{iface_stats.speed} Mbps" if iface_stats.speed else "N/A"
        w(f"| {iface_name} | {mac} | {status} | {speed} |")
    w("")

    # --- GPU ---
    w("## GPU")
    w("")
    gpus = ps_json(
        "Get-CimInstance Win32_VideoController | "
        "Select-Object Name, DriverVersion, AdapterRAM, VideoProcessor"
    )
    if gpus:
        # Read true VRAM from registry (64-bit qwMemorySize, no uint32 cap).
        # Registry subkey order does NOT match WMI order, so match by name.
        _gpu_reg_base = (
            r"SYSTEM\ControlSet001\Control\Class"
            r"\{4d36e968-e325-11ce-bfc1-08002be10318}"
        )
        registry_vram: dict[str, int] = {}
        for idx in range(16):  # scan up to 16 subkeys
            subkey = rf"{_gpu_reg_base}\{idx:04d}"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                    desc, _ = winreg.QueryValueEx(key, "DriverDesc")
                    val, _ = winreg.QueryValueEx(
                        key, "HardwareInformation.qwMemorySize"
                    )
                    registry_vram[desc] = int(val)
            except OSError:
                continue

        w("| GPU | Driver | VRAM | Processor |")
        w("|-----|--------|------|-----------|")
        for g in gpus:
            name = g.get("Name", "N/A")
            driver = g.get("DriverVersion", "N/A")
            # Prefer registry (accurate 64-bit) over WMI (uint32, caps at ~4 GB).
            raw_vram = registry_vram.get(name, 0) or g.get("AdapterRAM", 0)
            vram = format_bytes(raw_vram)
            proc = g.get("VideoProcessor", "N/A") or "N/A"
            w(f"| {name} | {driver} | {vram} | {proc} |")
    else:
        w("(no GPU information available)")
    w("")

    # --- Audio ---
    w("## Audio Devices")
    w("")
    w("```")
    audio = ps_json(
        "Get-CimInstance Win32_SoundDevice | Select-Object Name, Manufacturer, Status"
    )
    if audio:
        for a in audio:
            w(
                f"{a.get('Name', 'N/A')} - {a.get('Manufacturer', '')} [{a.get('Status', '')}]"
            )
    else:
        w("(no audio device info)")
    w("```")
    w("")

    # --- USB Devices ---
    w("## USB Devices")
    w("")
    w("```")
    usb_raw = run_ps(
        "Get-PnpDevice -Class USB -Status OK -ErrorAction SilentlyContinue | "
        "Select-Object FriendlyName, InstanceId | "
        "Format-Table -AutoSize | Out-String -Width 200"
    )
    w(usb_raw if usb_raw else "(no USB info available)")
    w("```")
    w("")

    HW_FILE.write_text("\n".join(lines), encoding="utf-8")


# ============================================================
# 2. SOFTWARE REPORT (semi-static)
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
    os_info = ps_json(
        "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime"
    )
    if os_info:
        o = os_info[0]
        w(f"| OS | {o.get('Caption', 'N/A')} |")
        w(f"| Version | {o.get('Version', 'N/A')} |")
        w(f"| Build | {o.get('BuildNumber', 'N/A')} |")
        w(f"| Architecture | {o.get('OSArchitecture', 'N/A')} |")
        install_date = o.get("InstallDate", "")
        if install_date:
            m = re.search(r"/Date\((\d+)\)", str(install_date))
            if m:
                install_date = datetime.datetime.fromtimestamp(
                    int(m.group(1)) / 1000
                ).strftime("%Y-%m-%d")
            w(f"| Install Date | {install_date} |")
    else:
        w(f"| OS | {platform.platform()} |")
        w(f"| Architecture | {platform.machine()} |")
    w(f"| Python | {platform.python_version()} |")
    w("")

    # --- Locale & Timezone ---
    w("## Locale & Timezone")
    w("")
    w("```")
    locale_info = run_ps(
        "Get-WinSystemLocale | Select-Object Name, DisplayName | Format-List | Out-String"
    )
    tz_info = run_ps(
        "Get-TimeZone | Select-Object Id, DisplayName | Format-List | Out-String"
    )
    w(locale_info if locale_info else "(locale info not available)")
    w(tz_info if tz_info else "(timezone info not available)")
    w("```")
    w("")

    # --- Software versions ---
    w("## Software Versions")
    w("")
    w("| Software | Version |")
    w("|----------|---------|")

    version_checks = [
        ("Python", "python --version"),
        ("Node.js", "node --version"),
        ("NPM", "npm --version"),
        ("Go", "go version"),
        ("Git", "git --version"),
        ("Docker", "docker --version"),
        ("Docker Compose", "docker compose version"),
        (
            "PowerShell",
            "powershell -NoProfile -Command $PSVersionTable.PSVersion.ToString()",
        ),
        ("Nginx", "nginx -v 2>&1"),
        ("PostgreSQL", "psql --version"),
        ("MySQL", "mysql --version"),
        ("Redis", "redis-server --version"),
        ("VS Code", "code --version"),
        ("WSL", "wsl --version 2>&1"),
    ]

    for name, cmd in version_checks:
        tool_name = cmd.split()[0]
        if which(tool_name) or tool_name == "powershell":
            ver = get_version(cmd)
            if ver and ver != "N/A":
                w(f"| {name} | {ver} |")
    w("")

    # --- Installed Programs ---
    w("## Installed Programs")
    w("")
    w("| Name | Version | Publisher |")
    w("|------|---------|-----------|")

    programs = ps_json(
        "Get-ItemProperty "
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
        "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -ne $null } | "
        "Sort-Object DisplayName | "
        "Select-Object DisplayName, DisplayVersion, Publisher -Unique"
    )
    for p in programs:
        name = (p.get("DisplayName") or "").replace("|", "/")
        ver = p.get("DisplayVersion", "") or ""
        pub = (p.get("Publisher") or "").replace("|", "/")
        # Skip registry placeholder entries
        if not name or name.startswith("${{"):
            continue
        w(f"| {name} | {ver} | {pub} |")
    w("")

    # --- Windows Features ---
    w("## Windows Optional Features (enabled)")
    w("")
    w("```")
    features = run_ps(
        "Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | "
        "Where-Object { $_.State -eq 'Enabled' } | "
        "Select-Object FeatureName | "
        "Sort-Object FeatureName | "
        "Format-Table -AutoSize | Out-String -Width 200"
    )
    w(features if features else "(not available - may require admin)")
    w("```")
    w("")

    # --- Services (enabled / auto-start) ---
    w("## Auto-Start Services")
    w("")
    w("```")
    services = run_ps(
        "Get-Service | Where-Object { $_.StartType -eq 'Automatic' } | "
        "Sort-Object DisplayName | "
        "Format-Table -Property DisplayName, Status, StartType -AutoSize | "
        "Out-String -Width 200"
    )
    w(services if services else "(no service info)")
    w("```")
    w("")

    # --- Scheduled Tasks ---
    w("## Scheduled Tasks (non-Microsoft)")
    w("")
    w("```")
    tasks = run_ps(
        "Get-ScheduledTask -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Author -notlike 'Microsoft*' -and $_.TaskName -notlike 'User_*' } | "
        "Select-Object TaskName, State, Author | "
        "Sort-Object TaskName | "
        "Format-Table -AutoSize | Out-String -Width 200"
    )
    w(tasks if tasks else "(no custom scheduled tasks)")
    w("```")
    w("")

    # --- Docker ---
    if which("docker"):
        w("## Docker Images")
        w("")
        w("```")
        w(run_cmd("docker images") or "(docker not running)")
        w("```")
        w("")
        w("## Docker Volumes")
        w("")
        w("```")
        w(run_cmd("docker volume ls") or "(none)")
        w("```")
        w("")
        w("## Docker Networks")
        w("")
        w("```")
        w(run_cmd("docker network ls") or "(none)")
        w("```")
        w("")

    # --- Users ---
    w("## Local Users")
    w("")
    w("| Name | Enabled | Description |")
    w("|------|---------|-------------|")
    users = ps_json("Get-LocalUser | Select-Object Name, Enabled, Description")
    for u in users:
        name = u.get("Name", "N/A")
        enabled = "Yes" if u.get("Enabled") else "No"
        desc = (u.get("Description") or "").replace("|", "/")
        w(f"| {name} | {enabled} | {desc} |")
    w("")

    # --- Listening Ports ---
    w("## Listening Ports")
    w("")
    w("| Protocol | Local Address | Port | PID | Process |")
    w("|----------|---------------|------|-----|---------|")
    try:
        conns = psutil.net_connections(kind="inet")
        seen = set()
        for c in sorted(conns, key=lambda x: x.laddr.port if x.laddr else 0):
            if c.status == "LISTEN" and c.laddr:
                key = (c.laddr.ip, c.laddr.port, c.pid)
                if key in seen:
                    continue
                seen.add(key)
                proto = "TCP"
                proc_name = ""
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "?"
                w(
                    f"| {proto} | {c.laddr.ip} | {c.laddr.port} | {c.pid or '-'} | {proc_name} |"
                )
    except psutil.AccessDenied:
        w("| (requires admin for full list) | | | | |")
    w("")

    # --- DNS ---
    w("## DNS Configuration")
    w("")
    w("```")
    dns = run_ps(
        "Get-DnsClientServerAddress -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ServerAddresses.Count -gt 0 } | "
        "Select-Object InterfaceAlias, ServerAddresses | "
        "Format-Table -AutoSize | Out-String -Width 200"
    )
    w(dns if dns else "(DNS info not available)")
    w("```")
    w("")

    SW_FILE.write_text("\n".join(lines), encoding="utf-8")


# ============================================================
# 3. STATE REPORT (live / runtime)
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
    uptime_str = f"{days}d {hours}h {minutes}m"

    w(f"| Uptime | {uptime_str} |")
    w(f"| Last Boot | {boot_time.strftime('%Y-%m-%d %H:%M:%S')} |")
    w(f"| Current Users | {len(psutil.users())} |")

    logged_users = psutil.users()
    if logged_users:
        user_names = ", ".join(set(u.name for u in logged_users))
        w(f"| Logged-in Users | {user_names} |")
    w("")

    # --- CPU usage ---
    w("## CPU Usage")
    w("")
    cpu_pct = psutil.cpu_percent(interval=1)
    w(f"- **CPU used**: {cpu_pct}%")
    w("")
    per_cpu = psutil.cpu_percent(interval=0.5, percpu=True)
    if per_cpu:
        w("| Core | Usage |")
        w("|------|-------|")
        for i, pct in enumerate(per_cpu):
            w(f"| Core {i} | {pct}% |")
    w("")

    freq = psutil.cpu_freq()
    if freq:
        w(f"- **Current frequency**: {freq.current:.0f} MHz")
        w("")

    # --- Memory usage ---
    w("## Memory Usage")
    w("")
    vmem = psutil.virtual_memory()
    w("| Property | Value |")
    w("|----------|-------|")
    w(f"| Total | {format_bytes(vmem.total)} |")
    w(f"| Used | {format_bytes(vmem.used)} ({vmem.percent}%) |")
    w(f"| Available | {format_bytes(vmem.available)} |")

    swap = psutil.swap_memory()
    w(f"| Swap Total | {format_bytes(swap.total)} |")
    w(f"| Swap Used | {format_bytes(swap.used)} ({swap.percent}%) |")
    w("")

    # --- Disk usage ---
    w("## Disk Usage")
    w("")
    w("| Drive | Total | Used | Free | Use% |")
    w("|-------|-------|------|------|------|")
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            pct = f"{usage.percent}%"
            w(
                f"| {part.mountpoint} | {format_bytes(usage.total)} | "
                f"{format_bytes(usage.used)} | {format_bytes(usage.free)} | {pct} |"
            )
        except (PermissionError, OSError):
            pass
    w("")

    # --- Disk I/O ---
    w("## Disk I/O (since boot)")
    w("")
    dio = psutil.disk_io_counters()
    if dio:
        w("| Metric | Value |")
        w("|--------|-------|")
        w(f"| Read | {format_bytes(dio.read_bytes)} |")
        w(f"| Write | {format_bytes(dio.write_bytes)} |")
        w(f"| Read Count | {dio.read_count:,} |")
        w(f"| Write Count | {dio.write_count:,} |")
    w("")

    # --- Battery (laptops) ---
    battery = psutil.sensors_battery()
    if battery:
        w("## Battery")
        w("")
        w("| Property | Value |")
        w("|----------|-------|")
        w(f"| Charge | {battery.percent}% |")
        plugged = "Yes" if battery.power_plugged else "No"
        w(f"| Plugged In | {plugged} |")
        if battery.secsleft > 0 and battery.secsleft != psutil.POWER_TIME_UNLIMITED:
            remain = f"{battery.secsleft // 3600}h {(battery.secsleft % 3600) // 60}m"
            w(f"| Time Remaining | {remain} |")
        w("")

    # --- Top processes by CPU ---
    w("## Top 15 Processes by CPU")
    w("")
    w("| PID | Name | CPU% | Mem% | Memory |")
    w("|-----|------|------|------|--------|")
    procs_cpu = []
    for p in psutil.process_iter(
        ["pid", "name", "cpu_percent", "memory_percent", "memory_info"]
    ):
        try:
            info = p.info
            # Skip idle/system noise
            if info.get("name") in ("System Idle Process",):
                continue
            procs_cpu.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    procs_cpu.sort(key=lambda x: x.get("cpu_percent") or 0, reverse=True)
    for p in procs_cpu[:15]:
        pid = p.get("pid", "?")
        name = (p.get("name") or "?")[:40]
        cpu = f"{p.get('cpu_percent', 0):.1f}"
        memp = f"{p.get('memory_percent', 0):.1f}"
        mem_info = p.get("memory_info")
        mem_str = format_bytes(mem_info.rss) if mem_info else "N/A"
        w(f"| {pid} | {name} | {cpu} | {memp} | {mem_str} |")
    w("")

    # --- Top processes by Memory ---
    w("## Top 15 Processes by Memory")
    w("")
    w("| PID | Name | Mem% | Memory | CPU% |")
    w("|-----|------|------|--------|------|")
    procs_cpu.sort(key=lambda x: x.get("memory_percent") or 0, reverse=True)
    for p in procs_cpu[:15]:
        pid = p.get("pid", "?")
        name = (p.get("name") or "?")[:40]
        cpu = f"{p.get('cpu_percent', 0):.1f}"
        memp = f"{p.get('memory_percent', 0):.1f}"
        mem_info = p.get("memory_info")
        mem_str = format_bytes(mem_info.rss) if mem_info else "N/A"
        w(f"| {pid} | {name} | {memp} | {mem_str} | {cpu} |")
    w("")

    # --- Running Services ---
    w("## Running Services")
    w("")
    w("```")
    running_svc = run_ps(
        "Get-Service | Where-Object { $_.Status -eq 'Running' } | "
        "Sort-Object DisplayName | "
        "Format-Table DisplayName, Status -AutoSize | "
        "Out-String -Width 200"
    )
    w(running_svc if running_svc else "(no service info)")
    w("```")
    w("")

    w("## Stopped Services (non-disabled)")
    w("")
    w("```")
    stopped_svc = run_ps(
        "Get-Service | Where-Object { $_.Status -eq 'Stopped' -and $_.StartType -ne 'Disabled' } | "
        "Sort-Object DisplayName | "
        "Format-Table DisplayName, Status, StartType -AutoSize | "
        "Out-String -Width 200"
    )
    w(stopped_svc if stopped_svc else "(none)")
    w("```")
    w("")

    # --- Docker containers ---
    if which("docker"):
        w("## Docker Containers")
        w("")
        w("### Running")
        w("")
        w("```")
        w(run_cmd("docker ps") or "(docker not running)")
        w("```")
        w("")
        w("### All (including stopped)")
        w("")
        w("```")
        w(run_cmd("docker ps -a") or "(docker not running)")
        w("```")
        w("")

    # --- Windows Update ---
    w("## Recent Windows Updates (last 20)")
    w("")
    w("```")
    updates = run_ps(
        "Get-HotFix -ErrorAction SilentlyContinue | "
        "Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | "
        "Select-Object -First 20 | "
        "Format-Table HotFixID, Description, InstalledOn -AutoSize | "
        "Out-String -Width 200"
    )
    w(updates if updates else "(update info not available)")
    w("```")
    w("")

    # --- Active Network Connections ---
    w("## Active Network Connections (top 30)")
    w("")
    w("| Protocol | Local | Remote | Status | PID | Process |")
    w("|----------|-------|--------|--------|-----|---------|")
    try:
        conns = psutil.net_connections(kind="inet")
        count = 0
        for c in sorted(conns, key=lambda x: x.status):
            if count >= 30:
                break
            if c.status in ("NONE",):
                continue
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            proc_name = ""
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "?"
            w(
                f"| {proto} | {local} | {remote} | {c.status} | {c.pid or '-'} | {proc_name} |"
            )
            count += 1
    except psutil.AccessDenied:
        w("| (requires admin for full list) | | | | | |")
    w("")

    # --- Network Addresses ---
    w("## Network Addresses")
    w("")
    w("| Interface | Family | Address | Netmask |")
    w("|-----------|--------|---------|---------|")
    for iface_name, iface_addrs in sorted(psutil.net_if_addrs().items()):
        if iface_name.startswith("Loopback"):
            continue
        for addr in iface_addrs:
            if addr.family == socket.AF_INET:
                family = "IPv4"
            elif addr.family == socket.AF_INET6:
                family = "IPv6"
            else:
                continue
            w(f"| {iface_name} | {family} | {addr.address} | {addr.netmask or '-'} |")
    w("")

    # --- Network I/O ---
    w("## Network I/O (since boot)")
    w("")
    nio = psutil.net_io_counters()
    if nio:
        w("| Metric | Value |")
        w("|--------|-------|")
        w(f"| Bytes Sent | {format_bytes(nio.bytes_sent)} |")
        w(f"| Bytes Recv | {format_bytes(nio.bytes_recv)} |")
        w(f"| Packets Sent | {nio.packets_sent:,} |")
        w(f"| Packets Recv | {nio.packets_recv:,} |")
        w(f"| Errors In | {nio.errin:,} |")
        w(f"| Errors Out | {nio.errout:,} |")
    w("")

    # --- Recent Event Logs ---
    w("## Recent System Events (last 30)")
    w("")
    w("```")
    events = run_ps(
        "Get-WinEvent -LogName System -MaxEvents 30 -ErrorAction SilentlyContinue | "
        "Format-Table TimeCreated, LevelDisplayName, ProviderName, Message -AutoSize -Wrap | "
        "Out-String -Width 250"
    )
    w(events if events else "(event log not available - may require admin)")
    w("```")
    w("")

    ST_FILE.write_text("\n".join(lines), encoding="utf-8")


# ============================================================
# 4. DISK SPACE REPORT (usage by category)
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
    w("| Drive | Total | Used | Free | Usage % |")
    w("|-------|-------|------|------|---------|")

    total_system_usage = 0
    accessible_mounts: list[str] = []
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            total_system_usage += usage.used
            accessible_mounts.append(part.mountpoint)
            pct = f"{usage.percent:.1f}%"
            w(
                f"| {part.mountpoint} | {format_bytes(usage.total)} | "
                f"{format_bytes(usage.used)} | {format_bytes(usage.free)} | {pct} |"
            )
        except (PermissionError, OSError):
            pass
    w("")
    w(f"**Total system storage used**: {format_bytes(total_system_usage)}")
    w("")

    # -- Scan all drives in parallel --
    print("  Scanning file categories (parallel)...")
    drive_results: dict[str, ScanResult] = {}

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(4, max(1, len(accessible_mounts)))
    ) as pool:
        futures = {
            pool.submit(_scan_volume, Path(m)): m for m in accessible_mounts
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

    # --- File Categories (all drives combined) ---
    w("## File Categories (all drives)")
    w("")

    global_stats: dict[str, list[int]] = {}
    global_scanned = 0
    for stats, _oext, _cdirs, scanned in drive_results.values():
        global_scanned += scanned
        for cat, (cnt, tot) in stats.items():
            if cat in global_stats:
                global_stats[cat][0] += cnt
                global_stats[cat][1] += tot
            else:
                global_stats[cat] = [cnt, tot]

    if global_stats:
        truncated = " (truncated on some drives)" if global_scanned >= 200_000 else ""
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

    # --- File Categories per Drive ---
    w("## File Categories per Drive")
    w("")

    for mount in accessible_mounts:
        w(f"### Drive {mount}")
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

    # --- Analyze User Directories ---
    w("## User Directory Analysis")
    w("")
    
    # Get all user profiles
    user_profiles = []
    users_dir = Path("C:/Users")
    if users_dir.exists():
        for item in users_dir.iterdir():
            if item.is_dir() and not item.name.startswith('.') and item.name not in ['All Users', 'Default', 'Default User', 'Public']:
                user_profiles.append(item)
    
    if not user_profiles:
        w("No user profiles found for analysis.")
    else:
        w(f"Found {len(user_profiles)} user profiles to analyze...")
        w("")
        
        for user_dir in user_profiles:
            w(f"### User: {user_dir.name}")
            w("")
            
            # Analyze main user directories
            dirs_to_analyze = [
                ("Desktop", user_dir / "Desktop"),
                ("Documents", user_dir / "Documents"),
                ("Downloads", user_dir / "Downloads"),
                ("Pictures", user_dir / "Pictures"),
                ("Videos", user_dir / "Videos"),
                ("Music", user_dir / "Music"),
                ("AppData/Local", user_dir / "AppData" / "Local"),
                ("AppData/Roaming", user_dir / "AppData" / "Roaming")
            ]
            
            user_total = 0
            for dir_name, dir_path in dirs_to_analyze:
                if dir_path.exists():
                    try:
                        dir_size = sum(f.stat().st_size for f in dir_path.rglob('*') if f.is_file())
                        user_total += dir_size
                        w(f"- **{dir_name}**: {format_bytes(dir_size)}")
                    except (OSError, PermissionError):
                        w(f"- **{dir_name}**: (Access denied)")
            
            w(f"**Total for {user_dir.name}**: {format_bytes(user_total)}")
            w("")

    # --- Program Files Analysis ---
    w("## Program Files Analysis")
    w("")
    
    program_dirs = [
        ("Program Files", Path("C:/Program Files")),
        ("Program Files (x86)", Path("C:/Program Files (x86)")),
        ("ProgramData", Path("C:/ProgramData"))
    ]
    
    for dir_name, dir_path in program_dirs:
        if dir_path.exists():
            try:
                total_size = 0
                large_dirs = []
                
                for item in dir_path.iterdir():
                    if item.is_dir():
                        try:
                            dir_size = sum(f.stat().st_size for f in item.rglob('*') if f.is_file())
                            total_size += dir_size
                            if dir_size > 100 * 1024 * 1024:  # Only show directories > 100MB
                                large_dirs.append((item.name, dir_size))
                        except (OSError, PermissionError):
                            continue
                
                w(f"### {dir_name}")
                w(f"**Total size**: {format_bytes(total_size)}")
                w("")
                
                if large_dirs:
                    large_dirs.sort(key=lambda x: x[1], reverse=True)
                    w("Top directories by size:")
                    w("")
                    w("| Directory | Size |")
                    w("|-----------|------|")
                    for name, size in large_dirs[:20]:  # Show top 20
                        w(f"| {name} | {format_bytes(size)} |")
                    w("")
                else:
                    w("No directories larger than 100MB found.")
                    w("")
                    
            except (OSError, PermissionError):
                w(f"Access denied for {dir_name}")
                w("")

    # --- Games Directory Analysis ---
    w("## Games Directory Analysis")
    w("")
    
    common_game_paths = [
        Path("C:/Games"),
        Path("C:/Steam"),
        Path("C:/Program Files (x86)/Steam"),
        Path("C:/Program Files/Epic Games"),
        Path("C:/Program Files/Origin Games"),
        Path("C:/Program Files (x86)/Origin Games"),
        Path("C:/GOG Games")
    ]
    
    found_games = False
    for game_path in common_game_paths:
        if game_path.exists():
            found_games = True
            try:
                total_size = sum(f.stat().st_size for f in game_path.rglob('*') if f.is_file())
                w(f"**{game_path}**: {format_bytes(total_size)}")
                
                # Show top game directories
                game_dirs = []
                for item in game_path.iterdir():
                    if item.is_dir():
                        try:
                            dir_size = sum(f.stat().st_size for f in item.rglob('*') if f.is_file())
                            if dir_size > 50 * 1024 * 1024:  # Only show > 50MB
                                game_dirs.append((item.name, dir_size))
                        except (OSError, PermissionError):
                            continue
                
                if game_dirs:
                    game_dirs.sort(key=lambda x: x[1], reverse=True)
                    w("| Game | Size |")
                    w("|------|------|")
                    for name, size in game_dirs[:15]:  # Show top 15 games
                        w(f"| {name} | {format_bytes(size)} |")
                w("")
                
            except (OSError, PermissionError):
                w(f"Access denied for {game_path}")
                w("")
    
    if not found_games:
        w("No common game directories found.")
        w("")

    # --- Large Files Summary ---
    w("## Large Files Summary")
    w("")
    w("Searching for files larger than 500MB across user directories...")
    w("")
    
    large_files = []
    search_dirs = [Path("C:/Users")] + [p for _, p in program_dirs]
    
    for base_dir in search_dirs:
        if not base_dir.exists():
            continue
            
        try:
            for file_path in base_dir.rglob('*'):
                try:
                    if file_path.is_file():
                        size = file_path.stat().st_size
                        if size > 500 * 1024 * 1024:  # > 500MB
                            large_files.append((file_path, size))
                            if len(large_files) >= 50:  # Limit to 50 files
                                break
                except (OSError, PermissionError):
                    continue
            if len(large_files) >= 50:
                break
        except (OSError, PermissionError):
            continue
    
    if large_files:
        large_files.sort(key=lambda x: x[1], reverse=True)
        w("| File Path | Size |")
        w("|-----------|------|")
        for file_path, size in large_files:
            # Truncate long paths for display
            path_str = str(file_path)
            if len(path_str) > 80:
                path_str = "..." + path_str[-77:]
            w(f"| {path_str} | {format_bytes(size)} |")
    else:
        w("No files larger than 500MB found in the searched directories.")
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

    # --- Global Other extensions (all drives combined) ---
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

    w("## Global Other Extensions (all drives)")
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

    # --- Other extensions per drive ---
    w("## Other Extensions per Drive")
    w("")

    for mount, (_stats, other_exts, _cat_dirs, _scanned) in drive_results.items():
        w(f"### Drive {mount}")
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
        full_path = f"{mount.rstrip('/').rstrip(chr(92))}{chr(92)}{subdir}" if subdir != "." else mount
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
                    f"{mount.rstrip('/').rstrip(chr(92))}{chr(92)}{subdir}"
                    if subdir != "." else mount
                )
                w(f"| `{full_path}` | {cnt:,} | {format_bytes(size)} |")
        w("")

    CP_FILE.write_text("\n".join(lines), encoding="utf-8")


# ============================================================
# Main
# ============================================================
def main() -> None:
    print("Generating Windows system inventory...")
    print()

    # State first: capture live metrics before heavy WMI queries
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
