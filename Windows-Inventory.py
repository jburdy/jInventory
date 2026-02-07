# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
Windows 11 System Inventory Script
Port of Linux-Inventory.sh for Windows 11 using Python 3.14+

Generates 3 Markdown reports:
  1. hardware.md   - static hardware info
  2. software.md   - installed software & versions
  3. state.md      - live runtime state (CPU, RAM, disk usage, processes...)
"""

import datetime
import json
import platform
import re
import shutil
import socket
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
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
HOSTNAME = socket.gethostname()

HW_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-0-hardware.md"
SW_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-1-software.md"
ST_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-2-state.md"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def sanitize(text: str) -> str:
    """Strip ANSI escape codes, null bytes, and non-ASCII characters."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    text = text.replace("\x00", "")  # strip null bytes (UTF-16 artifacts)
    return text.encode("ascii", errors="ignore").decode("ascii")


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


def format_bytes_gib(n: int | float) -> str:
    """Format bytes to GiB."""
    return f"{n / (1024**3):.1f} GiB"


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------
TOOLS_TO_CHECK = [
    "git",
    "python",
    "node",
    "npm",
    "docker",
    "go",
    "psql",
    "mysql",
    "redis-server",
    "nginx",
    "code",
    "wsl",
]

print("Tool detection:")
AVAILABLE_TOOLS: dict[str, bool] = {}
for tool in TOOLS_TO_CHECK:
    found = which(tool)
    AVAILABLE_TOOLS[tool] = found
    status = "[OK]     " if found else "[MISSING]"
    print(f"  {status} {tool}")
print()


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
    w(f"- **Total installed**: {format_bytes_gib(mem.total)}")
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
        w("| GPU | Driver | VRAM | Processor |")
        w("|-----|--------|------|-----------|")
        for g in gpus:
            name = g.get("Name", "N/A")
            driver = g.get("DriverVersion", "N/A")
            vram = format_bytes(g.get("AdapterRAM", 0))
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
    procs = []
    for p in psutil.process_iter(
        ["pid", "name", "cpu_percent", "memory_percent", "memory_info"]
    ):
        try:
            info = p.info
            procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    # Let CPU measurement settle
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

    print()
    print("Done. 3 files generated:")
    for label, path in [
        ("Hardware", HW_FILE),
        ("Software", SW_FILE),
        ("State", ST_FILE),
    ]:
        size = format_bytes(path.stat().st_size) if path.exists() else "?"
        print(f"  {label:10s}: {path} ({size})")


if __name__ == "__main__":
    main()
