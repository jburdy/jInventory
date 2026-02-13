# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
macOS System Inventory Script (Apple Silicon / modern Intel)

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
import plistlib
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
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
HOSTNAME = socket.gethostname().replace(".local", "")

HW_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-0-hardware.md"
SW_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-1-software.md"
ST_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-2-state.md"
DS_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-3-diskspace.md"
FS_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-4-filestats.md"
CP_FILE = SCRIPT_DIR / f"jInventory-{HOSTNAME}-5-catpaths.md"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def run(command: str, *, timeout: int = 30) -> str:
    """Run a shell command and return stdout."""
    try:
        r = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=True,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def run_stderr(command: str, *, timeout: int = 30) -> str:
    """Run a shell command and return stderr (some tools output there)."""
    try:
        r = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=True,
        )
        return r.stderr.strip()
    except Exception:
        return ""


def profiler_xml(data_type: str) -> list[dict]:
    """Run system_profiler with XML output and parse the plist."""
    try:
        r = subprocess.run(
            ["system_profiler", data_type, "-xml"],
            capture_output=True,
            timeout=30,
        )
        if r.returncode != 0 or not r.stdout:
            return []
        data = plistlib.loads(r.stdout)
        # system_profiler returns a list with one dict containing _items
        if data and isinstance(data, list) and "_items" in data[0]:
            return data[0]["_items"]
        return []
    except Exception:
        return []


def profiler_text(data_type: str) -> str:
    """Run system_profiler with text output."""
    return run(f"system_profiler {data_type}")


def which(name: str) -> bool:
    """Check if a command is available on PATH."""
    return shutil.which(name) is not None


def get_version(cmd: str) -> str:
    """Run a command and return its first line of output."""
    out = run(cmd) or run_stderr(cmd)
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


def sysctl(key: str) -> str:
    """Read a sysctl value."""
    return run(f"sysctl -n {key}")


def is_apple_silicon() -> bool:
    """Check if running on Apple Silicon."""
    return platform.machine() == "arm64"


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

    hw_items = profiler_xml("SPHardwareDataType")
    if hw_items:
        hw = hw_items[0]
        w(f"| Hostname | {HOSTNAME} |")
        w(f"| Model | {hw.get('machine_model', 'N/A')} |")
        w(f"| Model Name | {hw.get('machine_name', 'N/A')} |")
        # Apple Silicon shows chip_type, Intel shows cpu_type
        chip = hw.get("chip_type", hw.get("cpu_type", "N/A"))
        w(f"| Chip / CPU | {chip} |")
        w(f"| Serial Number | {hw.get('serial_number', 'N/A')} |")
        w(f"| Hardware UUID | {hw.get('platform_UUID', 'N/A')} |")
        if "number_processors" in hw:
            perf = hw.get("number_processors", "")
            w(f"| Total Cores | {perf} |")
        if "physical_memory" in hw:
            w(f"| Memory | {hw.get('physical_memory', 'N/A')} |")
        arch = "Apple Silicon (arm64)" if is_apple_silicon() else "Intel (x86_64)"
        w(f"| Architecture | {arch} |")
    else:
        w(f"| Hostname | {HOSTNAME} |")
        w(f"| Architecture | {platform.machine()} |")
    w("")

    # --- Chip Details (Apple Silicon) ---
    if is_apple_silicon():
        w("## Apple Silicon Details")
        w("")
        w("| Property | Value |")
        w("|----------|-------|")
        perf_cores = sysctl("hw.perflevel0.logicalcpu")
        eff_cores = sysctl("hw.perflevel1.logicalcpu")
        if perf_cores:
            w(f"| Performance Cores | {perf_cores} |")
        if eff_cores:
            w(f"| Efficiency Cores | {eff_cores} |")
        total_cpu = sysctl("hw.logicalcpu_max")
        if total_cpu:
            w(f"| Total Logical CPUs | {total_cpu} |")
        # Neural Engine (always present on Apple Silicon)
        w("| Neural Engine | Yes (16-core) |")
        # Rosetta 2
        rosetta = "Installed" if Path("/Library/Apple/usr/libexec/oah/libRosettaRuntime").exists() else "Not installed"
        w(f"| Rosetta 2 | {rosetta} |")
        w("")

    # --- CPU ---
    w("## CPU")
    w("")
    w("| Property | Value |")
    w("|----------|-------|")

    cpu_brand = sysctl("machdep.cpu.brand_string")
    if cpu_brand:
        w(f"| Model | {cpu_brand} |")
    w(f"| Architecture | {platform.machine()} |")
    w(f"| Physical Cores | {psutil.cpu_count(logical=False)} |")
    w(f"| Logical CPUs | {psutil.cpu_count(logical=True)} |")

    l2 = sysctl("hw.l2cachesize")
    l3 = sysctl("hw.l3cachesize")
    if l2:
        w(f"| L2 Cache | {format_bytes(int(l2))} |")
    if l3:
        w(f"| L3 Cache | {format_bytes(int(l3))} |")
    w("")

    # --- Memory (hardware) ---
    w("## Memory (hardware)")
    w("")
    mem = psutil.virtual_memory()
    w(f"- **Total installed**: {format_bytes(mem.total)}")
    w("")

    mem_items = profiler_xml("SPMemoryDataType")
    if mem_items:
        # Apple Silicon: unified memory, no DIMM slots
        if is_apple_silicon():
            for m in mem_items:
                mem_type = m.get("dimm_type", "Unified")
                w(f"- **Type**: {mem_type}")
                # Some models report sub-items
                sub_items = m.get("_items", [])
                if sub_items:
                    w("")
                    w("| Slot | Size | Type | Status |")
                    w("|------|------|------|--------|")
                    for s in sub_items:
                        slot = s.get("_name", "N/A")
                        size = s.get("dimm_size", "N/A")
                        stype = s.get("dimm_type", "N/A")
                        status = s.get("dimm_status", "N/A")
                        w(f"| {slot} | {size} | {stype} | {status} |")
        else:
            # Intel Mac: traditional DIMM slots
            w("| Slot | Size | Type | Speed | Status |")
            w("|------|------|------|-------|--------|")
            for m in mem_items:
                sub_items = m.get("_items", [])
                for s in sub_items:
                    slot = s.get("_name", "N/A")
                    size = s.get("dimm_size", "N/A")
                    stype = s.get("dimm_type", "N/A")
                    speed = s.get("dimm_speed", "N/A")
                    status = s.get("dimm_status", "N/A")
                    w(f"| {slot} | {size} | {stype} | {speed} | {status} |")
    w("")

    # --- Storage Devices ---
    w("## Storage Devices")
    w("")
    w("```")
    diskutil_out = run("diskutil list")
    w(diskutil_out if diskutil_out else "(no disk information available)")
    w("```")
    w("")

    storage_items = profiler_xml("SPStorageDataType")
    if storage_items:
        w("### Volume Details")
        w("")
        w("| Volume | Mount Point | FS | Capacity | Available | Type |")
        w("|--------|-------------|----| ---------|-----------|------|")
        for vol in storage_items:
            name = vol.get("_name", "N/A")
            mount = vol.get("mount_point", "N/A")
            fs = vol.get("file_system", "N/A")
            capacity = vol.get("size_in_bytes", 0)
            free = vol.get("free_space_in_bytes", 0)
            medium = vol.get("physical_drive", {}).get("medium_type", "N/A")
            w(f"| {name} | {mount} | {fs} | {format_bytes(capacity)} | {format_bytes(free)} | {medium} |")
        w("")

    # --- Disk Partitions (psutil) ---
    w("## Disk Partitions")
    w("")
    w("| Mount | Device | FS Type | Total | Used | Free |")
    w("|-------|--------|---------|-------|------|------|")
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            w(
                f"| {part.mountpoint} | {part.device} | {part.fstype} | "
                f"{format_bytes(usage.total)} | {format_bytes(usage.used)} | {format_bytes(usage.free)} |"
            )
        except (PermissionError, OSError):
            w(f"| {part.mountpoint} | {part.device} | {part.fstype} | N/A | N/A | N/A |")
    w("")

    # --- Network Interfaces ---
    w("## Network Interfaces")
    w("")
    w("| Interface | MAC | Status | Speed |")
    w("|-----------|-----|--------|-------|")

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for iface_name, iface_stats in sorted(stats.items()):
        if iface_name.startswith("lo"):
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
    w("## GPU / Display")
    w("")
    gpu_text = profiler_text("SPDisplaysDataType")
    if gpu_text:
        w("```")
        w(gpu_text)
        w("```")
    else:
        w("(no GPU information available)")
    w("")

    # --- Audio ---
    w("## Audio Devices")
    w("")
    w("```")
    audio_text = profiler_text("SPAudioDataType")
    w(audio_text if audio_text else "(no audio device info)")
    w("```")
    w("")

    # --- USB Devices ---
    w("## USB Devices")
    w("")
    w("```")
    usb_text = profiler_text("SPUSBDataType")
    w(usb_text if usb_text else "(no USB info available)")
    w("```")
    w("")

    # --- Bluetooth ---
    w("## Bluetooth")
    w("")
    w("```")
    bt_text = profiler_text("SPBluetoothDataType")
    w(bt_text if bt_text else "(no Bluetooth info available)")
    w("```")
    w("")

    # --- Thunderbolt ---
    tb_text = profiler_text("SPThunderboltDataType")
    if tb_text and "No" not in tb_text:
        w("## Thunderbolt")
        w("")
        w("```")
        w(tb_text)
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
    product_name = run("sw_vers -productName")
    product_version = run("sw_vers -productVersion")
    build_version = run("sw_vers -buildVersion")
    w(f"| OS | {product_name} |")
    w(f"| Version | {product_version} |")
    w(f"| Build | {build_version} |")
    w(f"| Architecture | {platform.machine()} |")
    w(f"| Kernel | {platform.release()} |")
    w(f"| Python | {platform.python_version()} |")
    w("")

    # --- Locale & Timezone ---
    w("## Locale & Timezone")
    w("")
    w("```")
    locale_info = run("defaults read NSGlobalDomain AppleLanguages 2>/dev/null")
    tz_info = run("systemsetup -gettimezone 2>/dev/null") or run("readlink /etc/localtime")
    w(f"Languages: {locale_info}" if locale_info else "Languages: (not available)")
    w(f"Timezone: {tz_info}" if tz_info else "Timezone: (not available)")
    w("```")
    w("")

    # --- Software versions ---
    w("## Software Versions")
    w("")
    w("| Software | Version |")
    w("|----------|---------|")

    version_checks = [
        ("Python", "python3 --version"),
        ("Node.js", "node --version"),
        ("NPM", "npm --version"),
        ("Go", "go version"),
        ("Git", "git --version"),
        ("Docker", "docker --version"),
        ("Docker Compose", "docker compose version"),
        ("Homebrew", "brew --version"),
        ("Nginx", "nginx -v 2>&1"),
        ("PostgreSQL", "psql --version"),
        ("MySQL", "mysql --version"),
        ("Redis", "redis-server --version"),
        ("VS Code", "code --version"),
        ("Xcode CLT", "xcode-select --version"),
        ("Tmux", "tmux -V"),
        ("Zsh", "zsh --version"),
    ]

    for name, cmd in version_checks:
        tool_name = cmd.split()[0]
        if which(tool_name) or tool_name == "zsh":
            ver = get_version(cmd)
            if ver and ver != "N/A":
                w(f"| {name} | {ver} |")
    w("")

    # --- Homebrew Packages ---
    if which("brew"):
        w("## Homebrew Packages")
        w("")

        # Formulae
        formulae = run("brew list --formula --versions")
        if formulae:
            formula_list = formulae.splitlines()
            w(f"### Formulae ({len(formula_list)} installed)")
            w("")
            w("```")
            w(formulae)
            w("```")
            w("")

        # Casks
        casks = run("brew list --cask --versions")
        if casks:
            cask_list = casks.splitlines()
            w(f"### Casks ({len(cask_list)} installed)")
            w("")
            w("```")
            w(casks)
            w("```")
            w("")

    # --- Applications ---
    w("## Applications (/Applications)")
    w("")
    w("| Application | Version |")
    w("|-------------|---------|")
    apps_dir = Path("/Applications")
    if apps_dir.exists():
        for app in sorted(apps_dir.glob("*.app")):
            plist_path = app / "Contents" / "Info.plist"
            version = "N/A"
            if plist_path.exists():
                try:
                    with open(plist_path, "rb") as f:
                        plist = plistlib.load(f)
                    version = plist.get("CFBundleShortVersionString", plist.get("CFBundleVersion", "N/A"))
                except Exception:
                    pass
            w(f"| {app.stem} | {version} |")
    w("")

    # --- Mac App Store apps ---
    if which("mas"):
        w("## Mac App Store Apps")
        w("")
        w("```")
        mas_list = run("mas list")
        w(mas_list if mas_list else "(no App Store apps or mas not configured)")
        w("```")
        w("")

    # --- Launch Daemons & Agents (non-Apple) ---
    w("## Launch Daemons (non-Apple)")
    w("")
    w("```")
    daemons = run(
        "ls /Library/LaunchDaemons/ 2>/dev/null | grep -v com.apple"
    )
    w(daemons if daemons else "(none)")
    w("```")
    w("")

    w("## Launch Agents (non-Apple)")
    w("")
    w("```")
    agents_sys = run("ls /Library/LaunchAgents/ 2>/dev/null | grep -v com.apple")
    agents_usr = run("ls ~/Library/LaunchAgents/ 2>/dev/null | grep -v com.apple")
    result = ""
    if agents_sys:
        result += "# /Library/LaunchAgents/\n" + agents_sys + "\n"
    if agents_usr:
        result += "# ~/Library/LaunchAgents/\n" + agents_usr
    w(result.strip() if result.strip() else "(none)")
    w("```")
    w("")

    # --- Startup Items (Login Items) ---
    w("## Login Items")
    w("")
    w("```")
    login_items = run(
        "osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null"
    )
    w(login_items if login_items else "(none or not accessible)")
    w("```")
    w("")

    # --- Docker ---
    if which("docker"):
        w("## Docker Images")
        w("")
        w("```")
        w(run("docker images") or "(Docker not running)")
        w("```")
        w("")
        w("## Docker Volumes")
        w("")
        w("```")
        w(run("docker volume ls") or "(none)")
        w("```")
        w("")
        w("## Docker Networks")
        w("")
        w("```")
        w(run("docker network ls") or "(none)")
        w("```")
        w("")

    # --- Users ---
    w("## Local Users")
    w("")
    w("| Name | UID | Admin | Home |")
    w("|------|-----|-------|------|")
    users_raw = run("dscl . list /Users UniqueID")
    if users_raw:
        for line in users_raw.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                uid = parts[-1]
                # Skip system users (UID < 500) and hidden users
                try:
                    if int(uid) < 500 and name != "root":
                        continue
                except ValueError:
                    continue
                if name.startswith("_"):
                    continue
                # Check admin group
                admin_check = run(f"dsmemberutil checkmembership -U {name} -G admin 2>/dev/null")
                is_admin = "Yes" if "is a member" in admin_check else "No"
                home = run(f"dscl . read /Users/{name} NFSHomeDirectory 2>/dev/null").replace("NFSHomeDirectory: ", "")
                w(f"| {name} | {uid} | {is_admin} | {home} |")
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
                proc_name = ""
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "?"
                w(
                    f"| TCP | {c.laddr.ip} | {c.laddr.port} | {c.pid or '-'} | {proc_name} |"
                )
    except psutil.AccessDenied:
        w("| (run with sudo for full list) | | | | |")
    w("")

    # --- DNS ---
    w("## DNS Configuration")
    w("")
    w("```")
    dns = run("scutil --dns 2>/dev/null | head -40")
    w(dns if dns else "(DNS info not available)")
    w("```")
    w("")

    # --- Security ---
    w("## Security")
    w("")
    w("| Property | Value |")
    w("|----------|-------|")
    sip_status = run("csrutil status 2>/dev/null")
    if sip_status:
        w(f"| SIP | {sip_status} |")
    gatekeeper = run("spctl --status 2>/dev/null")
    if gatekeeper:
        w(f"| Gatekeeper | {gatekeeper} |")
    filevault = run("fdesetup status 2>/dev/null")
    if filevault:
        w(f"| FileVault | {filevault} |")
    firewall = run("defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null")
    fw_states = {"0": "Off", "1": "On (specific services)", "2": "On (block all)"}
    if firewall:
        w(f"| Firewall | {fw_states.get(firewall, firewall)} |")
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
    w(f"| Active | {format_bytes(vmem.active)} |")
    w(f"| Inactive | {format_bytes(vmem.inactive)} |")
    w(f"| Wired | {format_bytes(vmem.wired)} |")

    swap = psutil.swap_memory()
    w(f"| Swap Total | {format_bytes(swap.total)} |")
    w(f"| Swap Used | {format_bytes(swap.used)} ({swap.percent}%) |")
    w("")

    # --- Memory Pressure ---
    w("## Memory Pressure")
    w("")
    w("```")
    mem_pressure = run("memory_pressure 2>/dev/null | tail -1")
    w(mem_pressure if mem_pressure else "(memory_pressure not available)")
    w("```")
    w("")

    # --- Disk usage ---
    w("## Disk Usage")
    w("")
    w("| Mount | Total | Used | Free | Use% |")
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
        # Additional macOS power info
        pmset_info = run("pmset -g batt 2>/dev/null")
        if pmset_info:
            # Extract cycle count if available
            cycle = run("ioreg -r -c AppleSmartBattery | grep CycleCount | awk '{print $NF}'")
            if cycle:
                w(f"| Cycle Count | {cycle} |")
            condition = run("system_profiler SPPowerDataType 2>/dev/null | grep Condition | awk -F': ' '{print $2}'")
            if condition:
                w(f"| Condition | {condition} |")
        w("")

    # --- Power / Thermal ---
    w("## Power & Thermal")
    w("")
    w("```")
    thermal = run("pmset -g therm 2>/dev/null")
    w(thermal if thermal else "(thermal info not available)")
    w("```")
    w("")

    # --- Top processes by CPU ---
    w("## Top 15 Processes by CPU")
    w("")
    w("| PID | Name | CPU% | Mem% | Memory |")
    w("|-----|------|------|------|--------|")
    procs_cpu = []
    # First pass to seed CPU measurement
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "memory_info"]):
        pass
    # Second pass for actual values
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "memory_info"]):
        try:
            info = p.info
            if info.get("name") in ("kernel_task", "idle"):
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

    # --- Docker containers ---
    if which("docker"):
        w("## Docker Containers")
        w("")
        w("### Running")
        w("")
        w("```")
        w(run("docker ps") or "(Docker not running)")
        w("```")
        w("")
        w("### All (including stopped)")
        w("")
        w("```")
        w(run("docker ps -a") or "(Docker not running)")
        w("```")
        w("")

    # --- Pending macOS Updates ---
    w("## Pending macOS Updates")
    w("")
    w("```")
    updates = run("softwareupdate -l 2>&1", timeout=15)
    w(updates if updates else "(unable to check for updates)")
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
        w("| (run with sudo for full list) | | | | | |")
    w("")

    # --- Network Addresses ---
    w("## Network Addresses")
    w("")
    w("| Interface | Family | Address | Netmask |")
    w("|-----------|--------|---------|---------|")
    for iface_name, iface_addrs in sorted(psutil.net_if_addrs().items()):
        if iface_name.startswith("lo"):
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

    # --- Wi-Fi Info ---
    wifi_info = run(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null"
    )
    if wifi_info:
        w("## Wi-Fi Status")
        w("")
        w("```")
        w(wifi_info)
        w("```")
        w("")

    # --- Recent System Logs ---
    w("## Recent System Logs (last 30)")
    w("")
    w("```")
    logs = run("log show --last 5m --style compact --predicate 'eventType == logEvent' 2>/dev/null | tail -30")
    w(logs if logs else "(log not available)")
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
    w("| Volume | Total | Used | Free | Usage % |")
    w("|--------|-------|------|------|---------|")

    total_system_usage = 0
    accessible_mounts: list[str] = []
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            total_system_usage += usage.used
            accessible_mounts.append(part.mountpoint)
            pct = f"{usage.percent:.1f}%"
            volume_name = part.mountpoint
            if part.mountpoint == "/":
                volume_name = "Macintosh HD"
            elif part.device:
                vi = run(f"diskutil info {part.device} 2>/dev/null | grep 'Volume Name:' | cut -d: -f2 | xargs")
                if vi:
                    volume_name = vi
            w(
                f"| {volume_name} | {format_bytes(usage.total)} | "
                f"{format_bytes(usage.used)} | {format_bytes(usage.free)} | {pct} |"
            )
        except (PermissionError, OSError):
            pass
    w("")
    w(f"**Total system storage used**: {format_bytes(total_system_usage)}")
    w("")

    # -- Scan all volumes in parallel --
    print("  Scanning file categories (parallel)...")
    volume_results: dict[str, ScanResult] = {}

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
                volume_results[mount] = result
                _, _, _, scanned = result
                print(f"    {mount}: {scanned:,} files scanned")
            except Exception as exc:
                print(f"    {mount}: scan failed ({exc})")
                volume_results[mount] = ({}, {}, {}, 0)

    # --- File Categories (all volumes combined) ---
    w("## File Categories (all volumes)")
    w("")

    global_stats: dict[str, list[int]] = {}
    global_scanned = 0
    for stats, _oext, _cdirs, scanned in volume_results.values():
        global_scanned += scanned
        for cat, (cnt, tot) in stats.items():
            if cat in global_stats:
                global_stats[cat][0] += cnt
                global_stats[cat][1] += tot
            else:
                global_stats[cat] = [cnt, tot]

    if global_stats:
        truncated = " (truncated on some volumes)" if global_scanned >= 200_000 else ""
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

    # --- File Categories per Volume ---
    w("## File Categories per Volume")
    w("")

    for mount in accessible_mounts:
        w(f"### Volume {mount}")
        w("")
        stats, _oext, _cdirs, scanned = volume_results.get(mount, ({}, {}, {}, 0))
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

    users_dir = Path("/Users")
    if users_dir.exists():
        skip_names = {"Shared", "Guest"}
        user_profiles = [
            item for item in users_dir.iterdir()
            if item.is_dir() and not item.name.startswith(".") and item.name not in skip_names
        ]

        for user_dir in sorted(user_profiles):
            w(f"### User: {user_dir.name}")
            w("")

            dirs_to_analyze = [
                "Desktop", "Documents", "Downloads", "Pictures",
                "Movies", "Music", "Library",
            ]
            user_total = 0
            for dir_name in dirs_to_analyze:
                dir_path = user_dir / dir_name
                if dir_path.is_dir():
                    try:
                        dir_size = sum(
                            f.stat().st_size for f in dir_path.rglob("*") if f.is_file()
                        )
                        user_total += dir_size
                        w(f"- **{dir_name}**: {format_bytes(dir_size)}")
                    except (OSError, PermissionError):
                        w(f"- **{dir_name}**: (Access denied)")

            if user_total > 0:
                w(f"**Total for {user_dir.name}**: {format_bytes(user_total)}")
            else:
                w(f"**Total for {user_dir.name}**: No accessible data")
            w("")

            # Detailed category analysis for important directories
            for dir_name in ("Documents", "Downloads", "Desktop"):
                dir_path = user_dir / dir_name
                if not dir_path.is_dir():
                    continue
                try:
                    dir_size = sum(
                        f.stat().st_size for f in dir_path.rglob("*") if f.is_file()
                    )
                except (OSError, PermissionError):
                    continue
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
    else:
        w("No /Users directory found.")
        w("")

    # --- Applications Analysis ---
    w("## Applications Analysis")
    w("")

    for apps_dir in [Path("/Applications"), Path("/System/Applications")]:
        if not apps_dir.exists():
            continue
        label = "Applications" if apps_dir.name == "Applications" else "System Applications"
        w(f"### {label}")
        w("")
        try:
            total_size = 0
            large_apps: list[tuple[str, int]] = []
            for app in apps_dir.glob("*.app"):
                try:
                    app_size = sum(f.stat().st_size for f in app.rglob("*") if f.is_file())
                    total_size += app_size
                    if app_size > 50 * 1024 * 1024:
                        large_apps.append((app.stem, app_size))
                except (OSError, PermissionError):
                    continue
            w(f"**Total size**: {format_bytes(total_size)}")
            w("")
            if large_apps:
                large_apps.sort(key=lambda x: x[1], reverse=True)
                w("| Application | Size |")
                w("|-------------|------|")
                for name, size in large_apps[:20]:
                    w(f"| {name} | {format_bytes(size)} |")
                w("")
        except (OSError, PermissionError):
            w(f"(access denied for {label})")
            w("")

    # --- Homebrew Size Analysis ---
    if which("brew"):
        w("## Homebrew Size Analysis")
        w("")
        prefix = run("brew --prefix") or "/opt/homebrew"
        cellar_path = Path(prefix) / "Cellar"
        if cellar_path.is_dir():
            w("### Top Formulae by Size")
            w("")
            w("| Package | Size |")
            w("|---------|------|")
            du_out = run(f"du -sk '{cellar_path}'/*/ 2>/dev/null | sort -rn | head -30", timeout=60)
            for line in du_out.splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    try:
                        size_kb = int(parts[0].strip())
                        name = Path(parts[1].strip().rstrip("/")).name
                        w(f"| {name} | {format_bytes(size_kb * 1024)} |")
                    except ValueError:
                        continue
            w("")

    # --- Games Directory Analysis ---
    w("## Games Directory Analysis")
    w("")

    found_games = False
    steam_apps = Path("/Applications/Steam.app")
    if steam_apps.exists():
        found_games = True
        w("### Steam")
        w("")
        user_name = run("whoami").strip()
        steam_library = Path(f"/Users/{user_name}/Library/Application Support/Steam/steamapps")
        if steam_library.is_dir():
            common = steam_library / "common"
            if common.is_dir():
                w("| Game | Size |")
                w("|------|------|")
                try:
                    for game_dir in sorted(common.iterdir()):
                        if not game_dir.is_dir():
                            continue
                        try:
                            gsize = sum(f.stat().st_size for f in game_dir.rglob("*") if f.is_file())
                            if gsize > 100 * 1024 * 1024:
                                w(f"| {game_dir.name} | {format_bytes(gsize)} |")
                        except (OSError, PermissionError):
                            continue
                except (OSError, PermissionError):
                    pass
                w("")

    if not found_games:
        w("No common game applications found (Steam, Epic Games, etc.).")
        w("")

    # --- Large Files Summary ---
    w("## Large Files Summary")
    w("")
    w("Searching for files larger than 500MB in user directories...")
    w("")

    large_files: list[tuple[Path, int]] = []
    for base_dir in [Path("/Users"), Path("/Applications")]:
        if not base_dir.exists():
            continue
        try:
            for file_path in base_dir.rglob("*"):
                try:
                    if file_path.is_file():
                        size = file_path.stat().st_size
                        if size > 500 * 1024 * 1024:
                            large_files.append((file_path, size))
                            if len(large_files) >= 50:
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
            path_str = str(file_path)
            if len(path_str) > 80:
                path_str = "..." + path_str[-77:]
            w(f"| {path_str} | {format_bytes(size)} |")
    else:
        w("No files larger than 500MB found in the searched directories.")
    w("")

    # --- System Directory Analysis ---
    w("## System Directory Analysis")
    w("")

    for dir_str in ("/System", "/Library", "/usr", "/opt", "/var"):
        dp = Path(dir_str)
        if dp.is_dir():
            try:
                dir_size = sum(f.stat().st_size for f in dp.rglob("*") if f.is_file())
                if dir_size > 0:
                    w(f"- **{dir_str}**: {format_bytes(dir_size)}")
            except (OSError, PermissionError):
                w(f"- **{dir_str}**: (Access denied)")
    w("")

    DS_FILE.write_text("\n".join(lines), encoding="utf-8")
    return volume_results


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

    # --- Global Other extensions (all volumes combined) ---
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

    w("## Global Other Extensions (all volumes)")
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

    # --- Other extensions per volume ---
    w("## Other Extensions per Volume")
    w("")

    for mount, (_stats, other_exts, _cat_dirs, _scanned) in drive_results.items():
        w(f"### Volume {mount}")
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
    print("Generating macOS system inventory...")
    print()

    # State first: capture live metrics before heavy system_profiler queries
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
