#!/bin/bash

# System inventory script - generates 3 Markdown reports:
#   1. hardware.md   - static hardware info (unchanged unless physical changes)
#   2. software.md   - installed software & versions (unchanged unless install/update)
#   3. state.md      - live runtime state (CPU, RAM, disk usage, processes...)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HW_FILE="${SCRIPT_DIR}/jInventory-${HOSTNAME}-0-hardware.md"
SW_FILE="${SCRIPT_DIR}/jInventory-${HOSTNAME}-1-software.md"
ST_FILE="${SCRIPT_DIR}/jInventory-${HOSTNAME}-2-state.md"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S %Z')
HOSTNAME=$(cat /proc/sys/kernel/hostname)

# Strip emojis, ANSI escape codes, and problematic Unicode
sanitize() {
    sed 's/\x1b\[[0-9;]*m//g' | LC_ALL=C tr -cd '\11\12\15\40-\176'
}

# ============================================================
# Tool detection - optional tools with graceful fallback
# ============================================================
declare -A TOOLS
for tool in sensors smartctl nvme expac checkupdates hostnamectl timedatectl localectl fwupdmgr dmidecode lshw; do
    command -v "$tool" &>/dev/null && TOOLS[$tool]=1 || TOOLS[$tool]=0
done

echo "Tool detection:"
for tool in "${!TOOLS[@]}"; do
    if [[ ${TOOLS[$tool]} -eq 1 ]]; then
        printf "  [OK]      %s\n" "$tool"
    else
        printf "  [MISSING] %s\n" "$tool"
    fi
done | sort
echo ""

# ============================================================
# 1. HARDWARE REPORT (static)
# ============================================================
generate_hardware() {
    local F="$HW_FILE"
    cat > "$F" <<EOF
# Hardware Inventory - ${HOSTNAME}

> Generated: ${TIMESTAMP}

EOF

    # --- System (hostnamectl) ---
    {
        echo "## System"
        echo ""
        echo "| Property | Value |"
        echo "|----------|-------|"
        if [[ ${TOOLS[hostnamectl]} -eq 1 ]]; then
            local chassis hw_vendor hw_model hw_serial fw_version fw_date fw_age
            local hctl
            hctl=$(hostnamectl 2>/dev/null | sanitize)
            chassis=$(echo "$hctl" | awk -F: '/Chassis/{gsub(/^[ \t]+/,"",$2); print $2}')
            hw_vendor=$(echo "$hctl" | awk -F: '/Hardware Vendor/{gsub(/^[ \t]+/,"",$2); print $2}')
            hw_model=$(echo "$hctl" | awk -F: '/Hardware Model/{gsub(/^[ \t]+/,"",$2); print $2}')
            hw_serial=$(echo "$hctl" | awk -F: '/Hardware Serial/{gsub(/^[ \t]+/,"",$2); print $2}')
            fw_version=$(echo "$hctl" | awk -F: '/Firmware Version/{gsub(/^[ \t]+/,"",$2); print $2}')
            fw_date=$(echo "$hctl" | awk -F: '/Firmware Date/{gsub(/^[ \t]+/,"",$2); print $2}')
            fw_age=$(echo "$hctl" | awk -F: '/Firmware Age/{gsub(/^[ \t]+/,"",$2); print $2}')
            echo "| Hostname | ${HOSTNAME} |"
            echo "| Chassis | ${chassis:-N/A} |"
            echo "| Manufacturer | ${hw_vendor:-N/A} |"
            echo "| Model | ${hw_model:-N/A} |"
            echo "| Serial | ${hw_serial:-N/A} |"
            echo "| Firmware Version | ${fw_version:-N/A} |"
            echo "| Firmware Date | ${fw_date:-N/A} |"
            echo "| Firmware Age | ${fw_age:-N/A} |"
        elif [[ ${TOOLS[dmidecode]} -eq 1 ]]; then
            local product manufacturer serial
            product=$(dmidecode -s system-product-name 2>/dev/null || echo "N/A")
            manufacturer=$(dmidecode -s system-manufacturer 2>/dev/null || echo "N/A")
            serial=$(dmidecode -s system-serial-number 2>/dev/null || echo "N/A")
            echo "| Hostname | ${HOSTNAME} |"
            echo "| Manufacturer | ${manufacturer} |"
            echo "| Product | ${product} |"
            echo "| Serial | ${serial} |"
        else
            echo "| Hostname | ${HOSTNAME} |"
        fi
        echo ""
    } >> "$F"

    # --- CPU ---
    {
        echo "## CPU"
        echo ""
        local model cores threads arch virt
        model=$(lscpu | grep 'Model name' | cut -d':' -f2 | xargs)
        cores=$(nproc)
        threads=$(lscpu | grep '^CPU(s):' | awk '{print $2}')
        arch=$(lscpu | grep 'Architecture' | awk '{print $2}')
        virt=$(lscpu | grep 'Virtualization' | cut -d':' -f2 | xargs 2>/dev/null || echo "N/A")
        echo "| Property | Value |"
        echo "|----------|-------|"
        echo "| Model | ${model} |"
        echo "| Architecture | ${arch} |"
        echo "| Cores | ${cores} |"
        echo "| Threads | ${threads} |"
        echo "| Virtualization | ${virt} |"
        echo ""
    } >> "$F"

    # --- RAM modules ---
    {
        echo "## Memory (hardware)"
        echo ""
        local total
        total=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
        echo "- **Total installed**: ${total} GiB"
        echo ""
        if [[ ${TOOLS[dmidecode]} -eq 1 ]]; then
            echo "| Slot | Size | Type | Speed |"
            echo "|------|------|------|-------|"
            dmidecode -t memory 2>/dev/null | awk '
                /^Memory Device$/ {slot=""; size=""; type=""; speed=""}
                /Locator:/ && !/Bank/ {gsub(/^[[:space:]]+Locator: /,"",$0); slot=$0}
                /Size:/ {gsub(/^[[:space:]]+Size: /,"",$0); size=$0}
                /Type:/ && !/Detail/ && !/Error/ {gsub(/^[[:space:]]+Type: /,"",$0); type=$0}
                /Speed:/ && !/Configured/ {gsub(/^[[:space:]]+Speed: /,"",$0); speed=$0}
                /^$/ && size != "" && size != "No Module Installed" {
                    print "| " slot " | " size " | " type " | " speed " |"
                }'
        fi
        echo ""
    } >> "$F"

    # --- Storage devices ---
    {
        echo "## Storage Devices"
        echo ""
        echo '```'
        lsblk -o NAME,SIZE,TYPE,FSTYPE,MODEL | grep -v loop | sanitize
        echo '```'
        echo ""
    } >> "$F"

    # --- Disk Details (smartctl) ---
    if [[ ${TOOLS[smartctl]} -eq 1 ]]; then
        {
            echo "## Disk Details (SMART)"
            echo ""
            echo "| Device | Model | Serial | Firmware | Capacity |"
            echo "|--------|-------|--------|----------|----------|"
            while read -r dev _rest; do
                [[ -z "$dev" ]] && continue
                local info
                info=$(smartctl -i "$dev" 2>/dev/null)
                if [[ $? -le 2 ]]; then
                    local d_model d_serial d_fw d_cap
                    d_model=$(echo "$info" | grep -E '(Device Model|Model Number)' | head -1 | cut -d: -f2 | xargs)
                    d_serial=$(echo "$info" | grep -i 'Serial Number' | head -1 | cut -d: -f2 | xargs)
                    d_fw=$(echo "$info" | grep -i 'Firmware' | head -1 | cut -d: -f2 | xargs)
                    d_cap=$(echo "$info" | grep -E '(User Capacity|Total NVM Capacity)' | head -1 | sed 's/.*\[//' | sed 's/\]//')
                    echo "| ${dev} | ${d_model:-N/A} | ${d_serial:-N/A} | ${d_fw:-N/A} | ${d_cap:-N/A} |"
                fi
            done < <(smartctl --scan 2>/dev/null | awk '{print $1}')
            echo ""
        } >> "$F"
    else
        echo "> smartctl not available - disk details skipped" >> "$F"
        echo "" >> "$F"
    fi

    # --- Network interfaces (physical) ---
    {
        echo "## Network Interfaces (physical)"
        echo ""
        echo "| Interface | MAC | Driver |"
        echo "|-----------|-----|--------|"
        for iface in /sys/class/net/*; do
            local name
            name=$(basename "$iface")
            [[ "$name" == lo ]] && continue
            [[ "$name" == veth* ]] && continue
            [[ "$name" == br-* ]] && continue
            [[ "$name" == docker* ]] && continue
            local mac driver
            mac=$(< "$iface/address")
            driver=$(basename "$(readlink -f "$iface/device/driver" 2>/dev/null)" 2>/dev/null || echo "N/A")
            echo "| ${name} | ${mac} | ${driver} |"
        done
        echo ""
    } >> "$F"

    # --- PCI / USB ---
    {
        echo "## PCI Devices"
        echo ""
        echo '```'
        lspci 2>/dev/null || echo "lspci not available"
        echo '```'
        echo ""
        echo "## USB Devices"
        echo ""
        echo '```'
        lsusb 2>/dev/null || echo "lsusb not available"
        echo '```'
        echo ""
    } >> "$F"

    # --- Firmware Inventory (fwupdmgr) ---
    if [[ ${TOOLS[fwupdmgr]} -eq 1 ]]; then
        {
            echo "## Firmware Inventory (fwupd)"
            echo ""
            echo '```'
            fwupdmgr get-devices 2>/dev/null | sanitize
            echo '```'
            echo ""
        } >> "$F"
    fi

    # --- Detailed hardware (lshw) ---
    if [[ ${TOOLS[lshw]} -eq 1 ]]; then
        {
            echo "## Detailed Hardware (lshw)"
            echo ""
            echo '```'
            lshw -short 2>/dev/null
            echo '```'
            echo ""
        } >> "$F"
    fi

    chmod 644 "$F"
}

# ============================================================
# 2. SOFTWARE REPORT (semi-static)
# ============================================================
generate_software() {
    local F="$SW_FILE"
    cat > "$F" <<EOF
# Software Inventory - ${HOSTNAME}

> Generated: ${TIMESTAMP}

EOF

    # --- OS ---
    {
        echo "## Operating System"
        echo ""
        local distro kernel sysarch
        distro=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
        kernel=$(uname -r)
        sysarch=$(uname -m)
        echo "| Property | Value |"
        echo "|----------|-------|"
        echo "| Distribution | ${distro} |"
        echo "| Kernel | ${kernel} |"
        echo "| Architecture | ${sysarch} |"
        echo ""
    } >> "$F"

    # --- System Locale & Keymap (localectl) ---
    if [[ ${TOOLS[localectl]} -eq 1 ]]; then
        {
            echo "## System Locale & Keymap"
            echo ""
            echo '```'
            localectl 2>/dev/null
            echo '```'
            echo ""
        } >> "$F"
    fi

    # --- Key software versions ---
    {
        echo "## Software Versions"
        echo ""
        echo "| Software | Version |"
        echo "|----------|---------|"
        echo "| Bash | $(bash --version | head -1 | awk '{print $4}') |"
        [ -x "$(command -v python3)" ] && echo "| Python | $(python3 --version 2>&1 | awk '{print $2}') |"
        [ -x "$(command -v node)" ] && echo "| Node.js | $(node --version 2>&1) |"
        [ -x "$(command -v npm)" ] && echo "| NPM | $(npm --version 2>&1) |"
        [ -x "$(command -v go)" ] && echo "| Go | $(go version 2>&1 | awk '{print $3}') |"
        [ -x "$(command -v git)" ] && echo "| Git | $(git --version | awk '{print $3}') |"
        [ -x "$(command -v docker)" ] && echo "| Docker | $(docker --version 2>&1 | awk '{print $3}' | tr -d ',') |"
        [ -x "$(command -v docker)" ] && echo "| Docker Compose | $(docker compose version 2>&1 | awk '{print $NF}') |"
        [ -x "$(command -v nginx)" ] && echo "| Nginx | $(nginx -v 2>&1 | awk -F/ '{print $2}') |"
        [ -x "$(command -v psql)" ] && echo "| PostgreSQL | $(psql --version | awk '{print $3}') |"
        [ -x "$(command -v mysql)" ] && echo "| MySQL | $(mysql --version | awk '{print $3}') |"
        [ -x "$(command -v redis-server)" ] && echo "| Redis | $(redis-server --version | awk '{print $3}' | cut -d= -f2) |"
        [ -x "$(command -v mosquitto)" ] && echo "| Mosquitto | $(mosquitto -h 2>&1 | head -1 | awk '{print $3}') |"
        [ -x "$(command -v fish)" ] && echo "| Fish | $(fish --version 2>&1 | awk '{print $NF}') |"
        [ -x "$(command -v tmux)" ] && echo "| Tmux | $(tmux -V 2>&1 | awk '{print $2}') |"
        echo ""
    } >> "$F"

    # --- Pacman packages ---
    {
        local pkg_count orphan_count
        pkg_count=$(pacman -Q 2>/dev/null | wc -l)
        orphan_count=$(pacman -Qtdq 2>/dev/null | wc -l)
        echo "## Installed Packages (${pkg_count} total, ${orphan_count} orphans)"
        echo ""
        echo "### Explicitly Installed"
        echo ""
        echo '```'
        pacman -Qe 2>/dev/null
        echo '```'
        echo ""
        echo "### Recent Package Changes (last 30)"
        echo ""
        echo '```'
        tail -100 /var/log/pacman.log 2>/dev/null | grep -E '\[ALPM\] (installed|upgraded|removed)' | tail -30
        echo '```'
        echo ""
    } >> "$F"

    # --- Top 20 Packages by Size (expac) ---
    if [[ ${TOOLS[expac]} -eq 1 ]]; then
        {
            echo "### Top 20 Packages by Size"
            echo ""
            echo "| Size | Package | Version |"
            echo "|------|---------|---------|"
            expac -H M '%m\t%n\t%v' 2>/dev/null | sort -rn | head -20 | while IFS=$'\t' read -r size name version; do
                printf "| %s | %s | %s |\n" "$size" "$name" "$version"
            done
            echo ""
        } >> "$F"
    fi

    # --- Systemd enabled services ---
    {
        echo "## Enabled Services"
        echo ""
        echo '```'
        systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null
        echo '```'
        echo ""
    } >> "$F"

    # --- Scheduled tasks ---
    {
        echo "## Scheduled Tasks"
        echo ""
        echo "### Crontab (root)"
        echo ""
        echo '```'
        crontab -l 2>/dev/null || echo "(no crontab for root)"
        echo '```'
        echo ""
        echo "### System Crontab"
        echo ""
        echo '```'
        cat /etc/crontab 2>/dev/null || echo "(empty)"
        echo '```'
        echo ""
        echo "### Systemd Timers"
        echo ""
        echo '```'
        systemctl list-timers --all --no-pager 2>/dev/null
        echo '```'
        echo ""
    } >> "$F"

    # --- Docker images ---
    if command -v docker &>/dev/null; then
        {
            echo "## Docker Images"
            echo ""
            echo '```'
            docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" 2>/dev/null
            echo '```'
            echo ""
            echo "## Docker Volumes"
            echo ""
            echo '```'
            docker volume ls 2>/dev/null
            echo '```'
            echo ""
            echo "## Docker Networks"
            echo ""
            echo '```'
            docker network ls 2>/dev/null
            echo '```'
            echo ""
            echo "## Docker Compose Projects"
            echo ""
            echo '```'
            docker compose ls 2>/dev/null
            echo '```'
            echo ""
        } >> "$F"
    fi

    # --- Users ---
    {
        echo "## Users with Login Shell"
        echo ""
        echo "| User | UID | Shell |"
        echo "|------|-----|-------|"
        grep -vE '(nologin|false)$' /etc/passwd | awk -F: '{print "| " $1 " | " $3 " | " $7 " |"}'
        echo ""
    } >> "$F"

    # --- Listening ports ---
    {
        echo "## Listening Ports"
        echo ""
        echo '```'
        ss -tulpn 2>/dev/null | grep LISTEN
        echo '```'
        echo ""
    } >> "$F"

    # --- DNS ---
    {
        echo "## DNS Configuration"
        echo ""
        echo '```'
        grep -v '^#' /etc/resolv.conf 2>/dev/null | grep -v '^$'
        echo '```'
        echo ""
    } >> "$F"

    chmod 644 "$F"
}

# ============================================================
# 3. STATE REPORT (live / runtime)
# ============================================================
generate_state() {
    local F="$ST_FILE"
    cat > "$F" <<EOF
# System State - ${HOSTNAME}

> Generated: ${TIMESTAMP}

EOF

    # --- Uptime / Load / NTP ---
    {
        echo "## System Status"
        echo ""
        echo "| Property | Value |"
        echo "|----------|-------|"
        echo "| Uptime | $(uptime -p) |"
        echo "| Last Boot | $(who -b | awk '{print $3, $4}') |"
        echo "| Current Users | $(who | wc -l) |"
        echo "| Load Average | $(cut -d' ' -f1-3 /proc/loadavg) |"
        if [[ ${TOOLS[timedatectl]} -eq 1 ]]; then
            local ntp_sync ntp_svc
            ntp_sync=$(timedatectl 2>/dev/null | awk -F: '/synchronized/{gsub(/^[ \t]+/,"",$2); print $2}')
            ntp_svc=$(timedatectl 2>/dev/null | awk -F: '/NTP service/{gsub(/^[ \t]+/,"",$2); print $2}')
            echo "| NTP Synchronized | ${ntp_sync:-N/A} |"
            echo "| NTP Service | ${ntp_svc:-N/A} |"
        fi
        echo ""
    } >> "$F"

    # --- CPU usage ---
    {
        echo "## CPU Usage"
        echo ""
        local cpu_idle cpu_used
        cpu_idle=$(top -bn1 | grep "Cpu(s)" | sed 's/.*, *\([0-9.]*\)%* id.*/\1/')
        cpu_used=$(awk "BEGIN {printf \"%.1f\", 100 - ${cpu_idle}}")
        echo "- **CPU used**: ${cpu_used}%"
        echo ""
    } >> "$F"

    # --- Memory usage ---
    {
        echo "## Memory Usage"
        echo ""
        echo '```'
        free -h
        echo '```'
        echo ""
        local mem_total mem_avail mem_pct
        mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
        mem_avail=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
        mem_pct=$(awk "BEGIN {printf \"%.1f\", 100 - (${mem_avail}/${mem_total}*100)}")
        echo "- **RAM used**: ${mem_pct}%"
        echo ""
    } >> "$F"

    # --- Temperatures & Fans (sensors) ---
    if [[ ${TOOLS[sensors]} -eq 1 ]]; then
        {
            echo "## Temperatures & Fans"
            echo ""
            echo '```'
            sensors 2>/dev/null | sanitize
            echo '```'
            echo ""
        } >> "$F"
    fi

    # --- Disk usage ---
    {
        echo "## Disk Usage"
        echo ""
        echo "| Filesystem | Size | Used | Avail | Use% | Mount |"
        echo "|------------|------|------|-------|------|-------|"
        df -h --output=source,size,used,avail,pcent,target 2>/dev/null \
            | grep -v tmpfs | grep -v devtmpfs | grep -v overlay | grep -v efivar | grep -v '/run/credentials' \
            | tail -n +2 \
            | while read -r src size used avail pct mnt; do
                [[ "$src" == "none" ]] && continue
                echo "| ${src} | ${size} | ${used} | ${avail} | ${pct} | ${mnt} |"
            done
        echo ""
        echo "### Top 10 Directories by Size"
        echo ""
        echo '```'
        du -h / --max-depth=1 2>/dev/null | sort -rh | head -10
        echo '```'
        echo ""
    } >> "$F"

    # --- Disk Health (smartctl + nvme) ---
    if [[ ${TOOLS[smartctl]} -eq 1 ]]; then
        {
            echo "## Disk Health"
            echo ""
            echo "| Device | Model | Health | Temp | Power-On | Wear |"
            echo "|--------|-------|--------|------|----------|------|"
            while read -r dev opts; do
                [[ -z "$dev" ]] && continue
                # Get health status
                local health_out health_status d_model d_temp d_hours d_wear
                health_out=$(smartctl -H $opts "$dev" 2>/dev/null)
                health_status="N/A"
                echo "$health_out" | grep -q "PASSED" && health_status="PASSED"
                echo "$health_out" | grep -q "FAILED" && health_status="FAILED"
                # Get model
                local info_out
                info_out=$(smartctl -i $opts "$dev" 2>/dev/null)
                d_model=$(echo "$info_out" | grep -E '(Device Model|Model Number)' | head -1 | cut -d: -f2 | xargs)
                d_temp="-"
                d_hours="-"
                d_wear="-"
                # NVMe specific: use nvme smart-log if available
                if echo "$opts" | grep -q "nvme" || echo "$dev" | grep -q "nvme"; then
                    if [[ ${TOOLS[nvme]} -eq 1 ]]; then
                        local nvme_dev
                        nvme_dev=$(echo "$dev" | sed 's/n1$//')
                        local smart_out
                        smart_out=$(nvme smart-log "$nvme_dev" 2>/dev/null)
                        d_temp=$(echo "$smart_out" | awk '/^temperature/{gsub(/[^0-9]/,"",$3); print $3 " C"}')
                        d_hours=$(echo "$smart_out" | awk '/^power_on_hours/{print $3}')
                        d_wear=$(echo "$smart_out" | awk '/^percentage_used/{print $3}')
                        local spare
                        spare=$(echo "$smart_out" | awk '/^available_spare[^_]/{print $3}')
                        [[ -n "$spare" ]] && d_wear="${d_wear} (spare: ${spare})"
                    fi
                else
                    # ATA/SATA: get from smartctl attributes
                    local attr_out
                    attr_out=$(smartctl -A $opts "$dev" 2>/dev/null)
                    d_temp=$(echo "$attr_out" | awk '/Temperature_Celsius|Airflow_Temperature/{print $10 " C"}' | head -1)
                    d_hours=$(echo "$attr_out" | awk '/Power_On_Hours/{print $10}' | head -1)
                fi
                echo "| ${dev} | ${d_model:-N/A} | ${health_status} | ${d_temp:--} | ${d_hours:--} h | ${d_wear:--} |"
            done < <(smartctl --scan 2>/dev/null | awk '{
                dev=$1
                opts=""
                for(i=2;i<=NF;i++) {
                    if($i=="#") break
                    opts=opts " " $i
                }
                print dev, opts
            }')
            echo ""
        } >> "$F"
    else
        echo "> smartctl not available - disk health skipped" >> "$F"
        echo "" >> "$F"
    fi

    # --- Top processes ---
    {
        echo "## Top Processes by CPU"
        echo ""
        echo '```'
        ps aux --sort=-%cpu | head -16
        echo '```'
        echo ""
        echo "## Top Processes by Memory"
        echo ""
        echo '```'
        ps aux --sort=-%mem | head -16
        echo '```'
        echo ""
    } >> "$F"

    # --- Running services ---
    {
        echo "## Running Services"
        echo ""
        echo '```'
        systemctl list-units --type=service --state=running --no-pager 2>/dev/null | sanitize
        echo '```'
        echo ""
        echo "## Failed Services"
        echo ""
        echo '```'
        systemctl list-units --type=service --state=failed --no-pager 2>/dev/null | sanitize
        echo '```'
        echo ""
    } >> "$F"

    # --- Docker containers ---
    if command -v docker &>/dev/null; then
        {
            echo "## Docker Containers"
            echo ""
            echo "### Running"
            echo ""
            echo '```'
            docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null
            echo '```'
            echo ""
            echo "### All (including stopped)"
            echo ""
            echo '```'
            docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null
            echo '```'
            echo ""
        } >> "$F"
    fi

    # --- Pending Updates (checkupdates) ---
    if [[ ${TOOLS[checkupdates]} -eq 1 ]]; then
        {
            echo "## Pending Updates"
            echo ""
            local updates
            updates=$(checkupdates 2>/dev/null)
            if [[ -n "$updates" ]]; then
                local update_count
                update_count=$(echo "$updates" | wc -l)
                echo "**${update_count} updates available:**"
                echo ""
                echo '```'
                echo "$updates"
                echo '```'
            else
                echo "System is up to date."
            fi
            echo ""
        } >> "$F"
    fi

    # --- Active connections ---
    {
        echo "## Active Network Connections"
        echo ""
        echo '```'
        ss -tunap 2>/dev/null | head -30
        echo '```'
        echo ""
    } >> "$F"

    # --- Network IPs ---
    {
        echo "## Network Addresses"
        echo ""
        echo '```'
        ip -br addr show 2>/dev/null | grep -v veth | grep -v 'br-' | grep -v docker
        echo '```'
        echo ""
    } >> "$F"

    # --- Recent logs ---
    {
        echo "## Recent System Logs (last 30)"
        echo ""
        echo '```'
        journalctl -n 30 --no-pager 2>/dev/null
        echo '```'
        echo ""
    } >> "$F"

    chmod 644 "$F"
}

# ============================================================
# Main
# ============================================================
echo "Generating system inventory..."

# State first: capture live metrics before heavy commands from hardware/software
generate_state
echo "  [OK] ${ST_FILE}"

generate_hardware
echo "  [OK] ${HW_FILE}"

generate_software
echo "  [OK] ${SW_FILE}"

echo ""
echo "Done. 3 files generated:"
echo "  Hardware : ${HW_FILE} ($(du -h "$HW_FILE" | cut -f1))"
echo "  Software : ${SW_FILE} ($(du -h "$SW_FILE" | cut -f1))"
echo "  State    : ${ST_FILE} ($(du -h "$ST_FILE" | cut -f1))"
