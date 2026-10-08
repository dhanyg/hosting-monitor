#!/usr/bin/env bash
#
# Hosting Monitor
# Panel: Auto-detect cPanel / DirectAdmin / generic Linux
# Purpose: Read-only monitoring for hosting servers.
#
# Modes:
#   disk [SIZE] [N]   Large files in /home, /var/log, /var/lib/mysql, /tmp
#   ssl                Expired public SSL certificates for hostname + hosted domains
#   service            Important hosting service status by hosting category
#   no argument        Run disk + ssl + service, each with its own report file
#
# Security:
# - Requires root for complete read access.
# - Does not modify monitored files or services.
# - Only intended writes are the monitoring report files under REPORT_DIR.
# - No eval and no shell execution of user-supplied values.
# - SSL connections are outbound and time-limited.
# - Filesystem scans use low CPU/I/O priority.

set -u
set -o pipefail
umask 077
export LC_ALL=C

SCRIPT_NAME="$(basename "$0")"
DEFAULT_MIN_SIZE="1G"
DEFAULT_LIMIT=30
MAX_LIMIT=1000
SSL_TIMEOUT=10

REPORT_DIR="/var/log/hosting-monitor"
REPORT_DATE="$(date +%Y%m%d)"
REPORT_FILE_PREFIX="${REPORT_DIR}/report-${REPORT_DATE}"

SCAN_DIRS=(
    "/home"
    "/var/log"
    "/var/lib/mysql"
    "/tmp"
)

MODE="all"
MIN_SIZE="$DEFAULT_MIN_SIZE"
LIMIT="$DEFAULT_LIMIT"
THRESHOLD_BYTES=0

CURRENT_EPOCH=0
PANEL="Unknown"
DOMAINS=()
declare -A SEEN_DOMAINS=()

usage() {
    cat <<USAGE
Usage:
  ${SCRIPT_NAME}                     Run all checks (disk + ssl + service)
  ${SCRIPT_NAME} disk [SIZE] [N]     Check large files
  ${SCRIPT_NAME} ssl                  Check expired public SSL certificates
  ${SCRIPT_NAME} service              Check selected hosting services

Disk arguments:
  SIZE   Minimum file size: integer + K/M/G/T (e.g. 100M, 1G, 10G)
         Default: ${DEFAULT_MIN_SIZE}
  N      Number of files to display: 1-${MAX_LIMIT}
         Default: ${DEFAULT_LIMIT}

Examples:
  ${SCRIPT_NAME}
  ${SCRIPT_NAME} disk
  ${SCRIPT_NAME} disk 100M
  ${SCRIPT_NAME} disk 1G 50
  ${SCRIPT_NAME} ssl
  ${SCRIPT_NAME} service
USAGE
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

require_root() {
    [[ "$(id -u)" -eq 0 ]] || fail "This script must be run as root."
}

require_cmd() {
    local cmd
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || fail "Required command not found: ${cmd}"
    done
}

is_valid_size() {
    local value unit
    [[ "$1" =~ ^[0-9]+[KMGT]$ ]] || return 1
    value="${1%?}"
    unit="${1: -1}"
    [[ "$value" =~ ^[1-9][0-9]{0,5}$ ]] || return 1
    [[ "$unit" =~ ^[KMGT]$ ]] || return 1
}

size_to_bytes() {
    local value="${1%?}"
    local unit="${1: -1}"
    local factor

    case "$unit" in
        K) factor=1024 ;;
        M) factor=$((1024 * 1024)) ;;
        G) factor=$((1024 * 1024 * 1024)) ;;
        T) factor=$((1024 * 1024 * 1024 * 1024)) ;;
        *) return 1 ;;
    esac

    printf '%s\n' "$((10#$value * factor))"
}

is_valid_limit() {
    [[ "$1" =~ ^[0-9]+$ ]] || return 1
    (( 10#$1 >= 1 && 10#$1 <= MAX_LIMIT )) || return 1
}

validate_args() {
    MODE="all"
    MIN_SIZE="$DEFAULT_MIN_SIZE"
    LIMIT="$DEFAULT_LIMIT"

    case "$#" in
        0)
            ;;
        1)
            case "$1" in
                disk|ssl|service)
                    MODE="$1"
                    ;;
                -h|--help|help)
                    usage
                    exit 0
                    ;;
                *)
                    fail "Invalid mode '$1'. Use: disk | ssl | service"
                    ;;
            esac
            ;;
        2|3)
            [[ "$1" == "disk" ]] || fail "Only 'disk' accepts additional arguments."
            MODE="disk"
            MIN_SIZE="$2"
            is_valid_size "$MIN_SIZE" || fail "Invalid size '$MIN_SIZE'. Use values such as 100M, 1G, 10G."
            if [[ "$#" -eq 3 ]]; then
                LIMIT="$3"
                is_valid_limit "$LIMIT" || fail "Invalid file count '$LIMIT'. Use an integer from 1 to ${MAX_LIMIT}."
            fi
            ;;
        *)
            fail "Too many arguments. Run '${SCRIPT_NAME} --help' for usage."
            ;;
    esac

    THRESHOLD_BYTES="$(size_to_bytes "$MIN_SIZE")" || fail "Unable to parse size '$MIN_SIZE'."
}

detect_panel() {
    if [[ -x /usr/local/cpanel/bin/whmapi1 || -x /usr/local/cpanel/cpanel ]]; then
        printf 'cPanel'
    elif [[ -x /usr/local/directadmin/directadmin ]]; then
        printf 'DirectAdmin'
    else
        printf 'Unknown'
    fi
}

print_header() {
    local run_mode="$1"
    local host ts
    host="$(hostname -f 2>/dev/null || hostname)"
    ts="$(date '+%Y-%m-%d %H:%M:%S %Z')"

    printf '%s\n' '============================================================'
    printf '%-12s: %s\n' 'Host' "$host"
    printf '%-12s: %s\n' 'Timestamp' "$ts"
    printf '%-12s: %s\n' 'Panel' "$PANEL"
    printf '%-12s: %s\n' 'Mode' "$run_mode"
    printf '%s\n\n' '============================================================'
}

format_size() {
    awk -v n="$1" '
        BEGIN {
            split("B KiB MiB GiB TiB PiB", u, " ")
            i=1
            while (n >= 1024 && i < 6) { n /= 1024; i++ }
            if (i == 1) printf "%.0f %s\n", n, u[i]
            else if (n >= 100) printf "%.0f %s\n", n, u[i]
            else if (n >= 10) printf "%.1f %s\n", n, u[i]
            else printf "%.2f %s\n", n, u[i]
        }
    '
}

monitor_disk() {
    local dir bytes threshold_expr
    local printed=0
    local file_count=0
    local metric_tmp scan_timestamp
    local size mtime owner path
    local escaped_path escaped_owner escaped_location location

    prepare_prom_dir

    metric_tmp="$(mktemp --tmpdir="$NODE_EXPORTER_TEXTFILE_DIR" ".hosting_monitor_large_files.XXXXXXXXXX")" ||
        fail "Unable to create temporary Prometheus metric file."

    chmod 644 -- "$metric_tmp" || {
        rm -f -- "$metric_tmp"
        fail "Unable to set permissions on temporary Prometheus metric file."
    }

    # Start a fresh metric file. It is installed atomically only after the scan completes.
    printf '%s\n' '# HELP hosting_monitor_large_file_size_bytes Size in bytes of each large file found by hosting-monitor.' >"$metric_tmp"
    printf '%s\n' '# TYPE hosting_monitor_large_file_size_bytes gauge' >>"$metric_tmp"

    printf '%s\n' '# HELP hosting_monitor_large_file_mtime_seconds Last modification time of each large file as Unix timestamp.' >>"$metric_tmp"
    printf '%s\n' '# TYPE hosting_monitor_large_file_mtime_seconds gauge' >>"$metric_tmp"

    printf '[1] LARGE FILES - TOP %s\n' "$LIMIT"
    printf '%-14s %-19s %-20s %s\n' 'SIZE' 'LAST MODIFIED' 'OWNER' 'PATH'
    printf '%-14s %-19s %-20s %s\n' '--------------' '-------------------' '--------------------' '------------------------------'

    # Find files >= threshold. NUL-delimited records safely handle whitespace/newlines in paths.
    bytes="$((THRESHOLD_BYTES - 1))"
    threshold_expr="+${bytes}c"

    while IFS=$'\t' read -r -d '' size mtime owner path; do
        [[ -n "$size" && -n "$path" ]] || continue

        printed=1
        ((file_count += 1))

        mtime="${mtime%%.*}"

        printf '%-14s %-19s %-20s %s\n' \
            "$(format_size "$size")" \
            "$(date -d "@${mtime}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || printf 'unknown')" \
            "$owner" "$path"

        # Export the same records shown by the report; no second filesystem scan.
        escaped_path="$(prom_escape_label "$path")"
        escaped_owner="$(prom_escape_label "$owner")"
        location="$(prom_location_for_path "$path")"
        escaped_location="$(prom_escape_label "$location")"

        printf 'hosting_monitor_large_file_size_bytes{path="%s",owner="%s",location="%s"} %s\n' \
            "$escaped_path" "$escaped_owner" "$escaped_location" "$size" >>"$metric_tmp"

        if [[ "$mtime" =~ ^[0-9]+$ ]]; then
            printf 'hosting_monitor_large_file_mtime_seconds{path="%s",owner="%s",location="%s"} %s\n' \
                "$escaped_path" "$escaped_owner" "$escaped_location" "$mtime" >>"$metric_tmp"
        fi
    done < <(
        {
            for dir in "${SCAN_DIRS[@]}"; do
                [[ -d "$dir" ]] || continue
                nice -n 19 ionice -c 3 find "$dir" -xdev -type f -size "$threshold_expr" \
                    -printf '%s\t%T@\t%u\t%p\0' 2>/dev/null || true
            done
        } | nice -n 19 ionice -c 3 sort -znr -k1,1 |
            nice -n 19 ionice -c 3 head -zn "$LIMIT"
    )

    if (( printed == 0 )); then
        printf '%s\n' '(no files found matching the threshold)'
    fi

    scan_timestamp="$(date -u +%s)"

    install_large_file_metrics "$metric_tmp" "$file_count" "$scan_timestamp"

    printf '\nMinimum size: %s | Locations: /home /var/log /var/lib/mysql /tmp\n\n' "$MIN_SIZE"
}
is_valid_hostname() {
    local h="$1"
    [[ ${#h} -le 253 ]] || return 1
    [[ "$h" != *..* ]] || return 1
    [[ "$h" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] && return 0
    [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]
}

append_domain() {
    local d="$1"
    d="${d%.}"
    d="${d,,}"
    [[ -n "$d" ]] || return 0
    is_valid_hostname "$d" || return 0
    if [[ -z "${SEEN_DOMAINS[$d]+x}" ]]; then
        SEEN_DOMAINS["$d"]=1
        DOMAINS+=("$d")
    fi
}

get_domains() {
    local d f
    DOMAINS=()
    SEEN_DOMAINS=()

    # Always include the web server hostname in the public SSL check.
    d="$(hostname -f 2>/dev/null || hostname)"
    append_domain "$d"

    # /etc/userdomains can be used as an optional domain source on cPanel
    # and on generic Linux servers used for testing/public SSL monitoring.
    # Do not use it on DirectAdmin so DirectAdmin domain discovery remains
    # isolated to its own data sources.
    if [[ "$PANEL" == "cPanel" || "$PANEL" == "Unknown" ]] && [[ -r /etc/userdomains ]]; then
        while IFS= read -r d; do
            append_domain "$d"
        done < <(awk -F: '{d=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", d); if (d != "") print d}' /etc/userdomains 2>/dev/null)
    fi

    case "$PANEL" in
        DirectAdmin)
            if [[ -r /etc/virtual/domainowners ]]; then
                while IFS= read -r d; do
                    append_domain "$d"
                done < <(awk -F: '{d=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", d); if (d != "") print d}' /etc/virtual/domainowners 2>/dev/null)
            fi

            for f in /usr/local/directadmin/data/users/*/domains.list; do
                [[ -f "$f" && -r "$f" ]] || continue
                while IFS= read -r d; do
                    append_domain "$d"
                done < "$f"
            done

            for f in /usr/local/directadmin/data/users/*/domains/*.pointers; do
                [[ -f "$f" && -r "$f" ]] || continue
                while IFS= read -r d; do
                    append_domain "$d"
                done < <(awk -F= '{d=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", d); if (d != "") print d}' "$f" 2>/dev/null)
            done
            ;;
    esac
}

format_expired_for() {
    local seconds="$1"
    local days hours mins

    if (( seconds < 60 )); then
        printf '<1m'
        return 0
    fi

    days=$((seconds / 86400))
    hours=$(((seconds % 86400) / 3600))
    mins=$(((seconds % 3600) / 60))

    if (( days > 0 )); then
        if (( hours > 0 )); then printf '%dd %dh' "$days" "$hours"; else printf '%dd' "$days"; fi
    elif (( hours > 0 )); then
        if (( mins > 0 )); then printf '%dh %dm' "$hours" "$mins"; else printf '%dh' "$hours"; fi
    else
        printf '%dm' "$mins"
    fi
}

check_one_ssl() {
    local domain="$1"
    local cert_end expiry_epoch expired_seconds

    cert_end="$(
        nice -n 19 ionice -c 3 timeout --signal=TERM --kill-after=2s "${SSL_TIMEOUT}s" \
            openssl s_client -connect "${domain}:443" -servername "$domain" -showcerts </dev/null 2>/dev/null |
        nice -n 19 ionice -c 3 openssl x509 -noout -enddate 2>/dev/null
    )"
    [[ "$cert_end" == notAfter=* ]] || return 2

    expiry_epoch="$(date -u -d "${cert_end#notAfter=}" +%s 2>/dev/null)" || return 2
    (( expiry_epoch < CURRENT_EPOCH )) || return 1

    expired_seconds=$((CURRENT_EPOCH - expiry_epoch))
    printf '%s\t%s\t%s\t%s\n' \
        "$domain" \
        "$(format_expired_for "$expired_seconds")" \
        "$expiry_epoch" \
        "$expired_seconds"
    return 0
}

prepare_ssl_metric() {
    SSL_METRIC_TMP=""

    [[ -d "$NODE_EXPORTER_TEXTFILE_DIR" ]] || {
        printf 'WARNING: Node Exporter textfile collector directory not found: %s\n' \
            "$NODE_EXPORTER_TEXTFILE_DIR" >&2
        return 0
    }

    SSL_METRIC_TMP="$(mktemp --tmpdir="$NODE_EXPORTER_TEXTFILE_DIR" '.hosting_monitor_ssl.XXXXXXXXXX')" || {
        printf 'WARNING: Unable to create SSL metric temporary file: %s\n' \
            "$NODE_EXPORTER_TEXTFILE_DIR" >&2
        SSL_METRIC_TMP=""
        return 0
    }

    chmod 644 -- "$SSL_METRIC_TMP" || {
        rm -f -- "$SSL_METRIC_TMP" 2>/dev/null || true
        SSL_METRIC_TMP=""
        printf 'WARNING: Unable to secure SSL metric temporary file.\n' >&2
        return 0
    }

    cat > "$SSL_METRIC_TMP" <<'METRICS'
# HELP hosting_monitor_ssl_expired SSL certificates that are currently expired.
# TYPE hosting_monitor_ssl_expired gauge
METRICS
}

write_ssl_metric() {
    local domain="$1"
    local expiry_epoch="$2"
    local expired_seconds="$3"

    [[ -n "$SSL_METRIC_TMP" ]] || return 0

    printf 'hosting_monitor_ssl_expired{domain="%s"} 1\n' \
        "$(prom_escape_label "$domain")" >> "$SSL_METRIC_TMP"

    printf 'hosting_monitor_ssl_expiry_timestamp_seconds{domain="%s"} %s\n' \
        "$(prom_escape_label "$domain")" "$expiry_epoch" >> "$SSL_METRIC_TMP"

    printf 'hosting_monitor_ssl_expired_for_seconds{domain="%s"} %s\n' \
        "$(prom_escape_label "$domain")" "$expired_seconds" >> "$SSL_METRIC_TMP"
}

finalize_ssl_metric() {
    local checked="$1"
    local expired="$2"
    local failed="$3"
    local check_ts

    [[ -n "$SSL_METRIC_TMP" ]] || return 0

    check_ts="$(date -u +%s)" || check_ts=0

    {
        printf '\n# HELP hosting_monitor_ssl_expired_count Number of SSL certificates currently expired.\n'
        printf '# TYPE hosting_monitor_ssl_expired_count gauge\n'
        printf 'hosting_monitor_ssl_expired_count %s\n' "$expired"

        printf '\n# HELP hosting_monitor_ssl_checked_count Number of domains checked for public SSL certificates.\n'
        printf '# TYPE hosting_monitor_ssl_checked_count gauge\n'
        printf 'hosting_monitor_ssl_checked_count %s\n' "$checked"

        printf '\n# HELP hosting_monitor_ssl_check_failures_count Number of SSL checks that failed or timed out.\n'
        printf '# TYPE hosting_monitor_ssl_check_failures_count gauge\n'
        printf 'hosting_monitor_ssl_check_failures_count %s\n' "$failed"

        printf '\n# HELP hosting_monitor_ssl_check_timestamp_seconds Unix timestamp when the SSL check completed.\n'
        printf '# TYPE hosting_monitor_ssl_check_timestamp_seconds gauge\n'
        printf 'hosting_monitor_ssl_check_timestamp_seconds %s\n' "$check_ts"
    } >> "$SSL_METRIC_TMP"

    if [[ -d "$SSL_METRIC_FILE" ]]; then
        printf 'WARNING: Refusing to replace SSL metric path because it is a directory: %s\n' \
            "$SSL_METRIC_FILE" >&2
        rm -f -- "$SSL_METRIC_TMP" 2>/dev/null || true
        SSL_METRIC_TMP=""
        return 0
    fi

    if [[ -L "$SSL_METRIC_FILE" ]]; then
        printf 'WARNING: Refusing to replace symlinked SSL metric file: %s\n' \
            "$SSL_METRIC_FILE" >&2
        rm -f -- "$SSL_METRIC_TMP" 2>/dev/null || true
        SSL_METRIC_TMP=""
        return 0
    fi

    mv -f -- "$SSL_METRIC_TMP" "$SSL_METRIC_FILE" || {
        printf 'WARNING: Unable to install SSL metric file: %s\n' "$SSL_METRIC_FILE" >&2
        rm -f -- "$SSL_METRIC_TMP" 2>/dev/null || true
    }

    chmod 644 -- "$SSL_METRIC_FILE" 2>/dev/null || true
    SSL_METRIC_TMP=""
}

monitor_ssl() {
    local domain result status ssl_domain expired_for expiry_epoch expired_seconds
    local checked=0 expired=0 failed=0

    prepare_ssl_metric

    CURRENT_EPOCH="$(date -u +%s)"
    get_domains

    printf '%s\n' '[2] EXPIRED SSL'
    printf '%-35s %s\n' 'DOMAIN' 'EXPIRED FOR'
    printf '%-35s %s\n' '-----------------------------------' '-----------'

    for domain in "${DOMAINS[@]}"; do
        ((checked += 1))
        result=""
        if result="$(check_one_ssl "$domain")"; then
            ssl_domain="${result%%$'\t'*}"
            result="${result#*$'\t'}"
            expired_for="${result%%$'\t'*}"
            result="${result#*$'\t'}"
            expiry_epoch="${result%%$'\t'*}"
            expired_seconds="${result#*$'\t'}"

            printf '%-35s %s\n' "$ssl_domain" "$expired_for"
            write_ssl_metric "$ssl_domain" "$expiry_epoch" "$expired_seconds"
            ((expired += 1))
        else
            status=$?
            (( status == 2 )) && ((failed += 1))
        fi
    done

    if (( expired == 0 )); then
        printf '%s\n' '(no expired certificates found)'
    fi

    finalize_ssl_metric "$checked" "$expired" "$failed"

    printf '\nChecked: %d | Expired: %d | Check failures/timeouts: %d\n\n' "$checked" "$expired" "$failed"
}

service_category_from_name() {
    local name="$1"

    case "$name" in
        # Web server and PHP-FPM backend.
        httpd|apache2|nginx|lsws|lshttpd|litespeed|openlitespeed|apache_php_fpm|nginx_php_fpm|php-fpm|php*-fpm)
            printf '%s\n' 'web server'
            ;;
        # DNS server daemon only.
        named|pdns|pdns-server|powerdns)
            printf '%s\n' 'dns server'
            ;;
        # Database server daemons.
        mysql|mysqld|mariadb|postgresql|postgresql-*)
            printf '%s\n' 'database'
            ;;
        # Mail transport, mailbox and mail filtering services.
        exim|exim4|postfix|sendmail|dovecot|courier-imap|courier-imaps|imap|imap4|pop|pop3|lmtp|rspamd|spamd|spamassassin)
            printf '%s\n' 'mail server'
            ;;
        # FTP server daemons.
        ftpd|pure-ftpd|pureftpd|proftpd|vsftpd)
            printf '%s\n' 'ftp server'
            ;;
        # Core control-panel service.
        cpsrvd|cpsrvd-*|cpanel_php_fpm|directadmin)
            printf '%s\n' 'panel server'
            ;;
        *)
            return 1
            ;;
    esac
}

print_service_row() {
    printf '%-12s %-28s %s\n' "$1" "$2" "$3"
}

prom_location_for_path() {
    local path="$1"
    local dir

    for dir in "${SCAN_DIRS[@]}"; do
        case "$path" in
            "$dir"/*|"$dir")
                printf '%s' "$dir"
                return 0
                ;;
        esac
    done

    printf '%s' 'unknown'
}

prepare_prom_dir() {
    [[ -L "$NODE_EXPORTER_TEXTFILE_DIR" ]] &&
        fail "Refusing to use a symlinked Node Exporter textfile directory: ${NODE_EXPORTER_TEXTFILE_DIR}"

    [[ -e "$NODE_EXPORTER_TEXTFILE_DIR" && ! -d "$NODE_EXPORTER_TEXTFILE_DIR" ]] &&
        fail "Node Exporter textfile path exists but is not a directory: ${NODE_EXPORTER_TEXTFILE_DIR}"

    if [[ ! -d "$NODE_EXPORTER_TEXTFILE_DIR" ]]; then
        mkdir -p -- "$NODE_EXPORTER_TEXTFILE_DIR" ||
            fail "Unable to create Node Exporter textfile directory: ${NODE_EXPORTER_TEXTFILE_DIR}"

        # Node Exporter must be able to traverse and read the directory.
        chmod 755 -- "$NODE_EXPORTER_TEXTFILE_DIR" ||
            fail "Unable to set permissions on Node Exporter textfile directory: ${NODE_EXPORTER_TEXTFILE_DIR}"
    fi
}

install_large_file_metrics() {
    local metric_tmp="$1"
    local file_count="$2"
    local scan_timestamp="$3"

    printf '%s\n' '# HELP hosting_monitor_large_file_count Number of large files exported by hosting-monitor.' >>"$metric_tmp"
    printf '%s\n' '# TYPE hosting_monitor_large_file_count gauge' >>"$metric_tmp"
    printf 'hosting_monitor_large_file_count %s\n' "$file_count" >>"$metric_tmp"

    printf '\n%s\n' '# HELP hosting_monitor_large_file_scan_timestamp_seconds Unix timestamp of the latest completed large-file scan.' >>"$metric_tmp"
    printf '%s\n' '# TYPE hosting_monitor_large_file_scan_timestamp_seconds gauge' >>"$metric_tmp"
    printf 'hosting_monitor_large_file_scan_timestamp_seconds %s\n' "$scan_timestamp" >>"$metric_tmp"

    printf '\n%s\n' '# HELP hosting_monitor_large_file_threshold_bytes Minimum size in bytes used by the latest large-file scan.' >>"$metric_tmp"
    printf '%s\n' '# TYPE hosting_monitor_large_file_threshold_bytes gauge' >>"$metric_tmp"
    printf 'hosting_monitor_large_file_threshold_bytes %s\n' "$THRESHOLD_BYTES" >>"$metric_tmp"

    [[ ! -d "$PROM_METRIC_FILE" ]] ||
        fail "Prometheus metric path is a directory: ${PROM_METRIC_FILE}"

    [[ -L "$PROM_METRIC_FILE" ]] &&
        fail "Refusing to replace symlinked Prometheus metric file: ${PROM_METRIC_FILE}"

    mv -f -- "$metric_tmp" "$PROM_METRIC_FILE" ||
        fail "Unable to install Prometheus metric file: ${PROM_METRIC_FILE}"

    chmod 644 -- "$PROM_METRIC_FILE" ||
        fail "Unable to set permissions on Prometheus metric file."

    printf 'Prometheus metrics saved: %s\n' "$PROM_METRIC_FILE" >&2
}

# Node Exporter Textfile Collector output for service metrics.
NODE_EXPORTER_TEXTFILE_DIR="${NODE_EXPORTER_TEXTFILE_DIR:-/var/lib/node_exporter/textfile_collector}"
PROM_METRIC_FILE="${NODE_EXPORTER_TEXTFILE_DIR}/hosting_monitor_large_files.prom"
SERVICE_METRIC_FILE="${NODE_EXPORTER_TEXTFILE_DIR}/hosting_monitor_services.prom"
SSL_METRIC_FILE="${NODE_EXPORTER_TEXTFILE_DIR}/hosting_monitor_ssl.prom"
SERVICE_METRIC_TMP=""
SSL_METRIC_TMP=""

prom_escape_label() {
    local value="$1"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    printf '%s' "$value"
}

prepare_service_metric() {
    SERVICE_METRIC_TMP=""

    [[ -d "$NODE_EXPORTER_TEXTFILE_DIR" ]] || {
        printf 'WARNING: Node Exporter textfile collector directory not found: %s\n' \
            "$NODE_EXPORTER_TEXTFILE_DIR" >&2
        return 0
    }

    SERVICE_METRIC_TMP="$(mktemp --tmpdir="$NODE_EXPORTER_TEXTFILE_DIR" '.hosting_monitor_services.XXXXXXXXXX')" || {
        printf 'WARNING: Unable to create service metric temporary file: %s\n' \
            "$NODE_EXPORTER_TEXTFILE_DIR" >&2
        SERVICE_METRIC_TMP=""
        return 0
    }

    chmod 644 -- "$SERVICE_METRIC_TMP" || {
        rm -f -- "$SERVICE_METRIC_TMP" 2>/dev/null || true
        SERVICE_METRIC_TMP=""
        printf 'WARNING: Unable to secure service metric temporary file.\n' >&2
        return 0
    }

    cat > "$SERVICE_METRIC_TMP" <<'METRICS'
# HELP hosting_monitor_service_status Current status of a monitored hosting service.
# TYPE hosting_monitor_service_status gauge
METRICS
}

write_service_metric() {
    local service="$1" category="$2" status="$3"
    [[ -n "$SERVICE_METRIC_TMP" ]] || return 0

    printf 'hosting_monitor_service_status{service="%s",category="%s",status="%s"} 1\n' \
        "$(prom_escape_label "$service")" \
        "$(prom_escape_label "$category")" \
        "$(prom_escape_label "$status")" >> "$SERVICE_METRIC_TMP"
}

finalize_service_metric() {
    local check_ts
    [[ -n "$SERVICE_METRIC_TMP" ]] || return 0

    check_ts="$(date -u +%s)" || check_ts=0
    {
        printf '\n# HELP hosting_monitor_service_check_timestamp_seconds Unix timestamp when the service check completed.\n'
        printf '# TYPE hosting_monitor_service_check_timestamp_seconds gauge\n'
        printf 'hosting_monitor_service_check_timestamp_seconds %s\n' "$check_ts"
    } >> "$SERVICE_METRIC_TMP"

    if [[ -L "$SERVICE_METRIC_FILE" ]]; then
        printf 'WARNING: Refusing to replace symlinked service metric file: %s\n' "$SERVICE_METRIC_FILE" >&2
        rm -f -- "$SERVICE_METRIC_TMP" 2>/dev/null || true
        SERVICE_METRIC_TMP=""
        return 0
    fi

    mv -f -- "$SERVICE_METRIC_TMP" "$SERVICE_METRIC_FILE" || {
        printf 'WARNING: Unable to install service metric file: %s\n' "$SERVICE_METRIC_FILE" >&2
        rm -f -- "$SERVICE_METRIC_TMP" 2>/dev/null || true
    }
    SERVICE_METRIC_TMP=""
}

monitor_cpanel_services() {
    local whmapi api_output
    whmapi="/usr/local/cpanel/bin/whmapi1"
    [[ -x "$whmapi" ]] || whmapi="$(command -v whmapi1 2>/dev/null || true)"
    [[ -n "$whmapi" && -x "$whmapi" ]] || return 1

    api_output="$(nice -n 19 ionice -c 3 "$whmapi" --output=yaml servicestatus 2>/dev/null)" || return 1
    [[ -n "$api_output" ]] || return 1

    printf '%s\n' '[3] HOSTING SERVICES'
    printf '%-12s %-28s %s\n' 'CATEGORY' 'SERVICE' 'STATUS'
    printf '%-12s %-28s %s\n' '------------' '----------------------------' '------------'

    # Raw WHM API output is parsed internally and never printed.
    printf '%s\n' "$api_output" | awk -v metric_file="$SERVICE_METRIC_TMP" '
        function category(n) {
            if (n ~ /^(httpd|apache2|nginx|lsws|lshttpd|litespeed|openlitespeed|apache_php_fpm|nginx_php_fpm|php-fpm|php.*-fpm)$/) return "web server"
            if (n ~ /^(named|pdns|pdns-server|powerdns)$/) return "dns server"
            if (n ~ /^(mysql|mysqld|mariadb|postgresql)/) return "database"
            if (n ~ /^(exim|exim4|postfix|sendmail|dovecot|courier-imap|courier-imaps|imap|imap4|pop|pop3|lmtp|rspamd|spamd|spamassassin)$/) return "mail server"
            if (n ~ /^(ftpd|pure-ftpd|pureftpd|proftpd|vsftpd)$/) return "ftp server"
            if (n ~ /^(cpsrvd|cpanel_php_fpm|directadmin)(-|$)/) return "panel server"
            return ""
        }
        function flush() {
            if (name != "" && installed == "1" && monitored == "1") {
                cat=category(name)
                if (cat != "") {
                    if (running == "1") status="active"
                    else if (enabled != "1") status="disabled"
                    else status="down"
                    printf "%-12s %-28s %s\n", cat, name, status
                    if (metric_file != "") {
                        gsub(/\\/, "\\\\", name)
                        gsub(/"/, "\\\"", name)
                        gsub(/\\/, "\\\\", cat)
                        gsub(/"/, "\\\"", cat)
                        gsub(/\\/, "\\\\", status)
                        gsub(/"/, "\\\"", status)
                        printf "hosting_monitor_service_status{service=\"%s\",category=\"%s\",status=\"%s\"} 1\n", name, cat, status >> metric_file
                    }
                    count++
                }
            }
        }
        /^[[:space:]]*-[[:space:]]*$/ {
            flush()
            name=""; enabled=""; installed=""; monitored=""; running=""
            next
        }
        /^[[:space:]]*name:/ { sub(/^[[:space:]]*name:[[:space:]]*/, ""); name=$0; next }
        /^[[:space:]]*enabled:/ { sub(/^[[:space:]]*enabled:[[:space:]]*/, ""); enabled=$0; next }
        /^[[:space:]]*installed:/ { sub(/^[[:space:]]*installed:[[:space:]]*/, ""); installed=$0; next }
        /^[[:space:]]*monitored:/ { sub(/^[[:space:]]*monitored:[[:space:]]*/, ""); monitored=$0; next }
        /^[[:space:]]*running:/ { sub(/^[[:space:]]*running:[[:space:]]*/, ""); running=$0; next }
        END {
            flush()
            if (count == 0) print "(no monitored services in the selected categories reported by cPanel)"
        }
    '
    printf '\n'
    return 0
}

monitor_systemd_services() {
    local unit state name category
    local -a units=()
    declare -A seen_units=()

    while IFS= read -r unit; do
        [[ -n "$unit" && "$unit" == *.service ]] || continue
        name="${unit%.service}"
        category="$(service_category_from_name "$name" 2>/dev/null || true)"
        [[ -n "$category" ]] || continue
        [[ -n "${seen_units[$unit]+x}" ]] && continue
        seen_units["$unit"]=1
        units+=("$unit")
    done < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{print $1}')

    printf '%s\n' '[3] HOSTING SERVICES'
    printf '%-12s %-28s %s\n' 'CATEGORY' 'SERVICE' 'STATUS'
    printf '%-12s %-28s %s\n' '------------' '----------------------------' '------------'

    if (( ${#units[@]} == 0 )); then
        printf '%s\n' '(no matching services found in the selected categories)'
        printf '\n'
        return 0
    fi

    for unit in "${units[@]}"; do
        name="${unit%.service}"
        category="$(service_category_from_name "$name" 2>/dev/null || true)"
        state="$(nice -n 19 ionice -c 3 systemctl is-active "$unit" 2>/dev/null || true)"
        [[ -n "$state" ]] || state="unknown"
        print_service_row "$category" "$name" "$state"
        write_service_metric "$name" "$category" "$state"
    done
    printf '\n'
}

monitor_service() {
    local service_rc=0

    prepare_service_metric

    case "$PANEL" in
        cPanel)
            if monitor_cpanel_services; then
                service_rc=0
            else
                monitor_systemd_services
                service_rc=$?
            fi
            ;;
        DirectAdmin|Unknown)
            monitor_systemd_services
            service_rc=$?
            ;;
    esac

    finalize_service_metric
    return "$service_rc"
}

prepare_report_dir() {
    [[ -L "$REPORT_DIR" ]] && fail "Refusing to use a symlinked report directory: ${REPORT_DIR}"
    [[ -e "$REPORT_DIR" && ! -d "$REPORT_DIR" ]] && fail "Report path exists but is not a directory: ${REPORT_DIR}"

    if [[ ! -d "$REPORT_DIR" ]]; then
        mkdir -p -- "$REPORT_DIR" || fail "Unable to create report directory: ${REPORT_DIR}"
    fi

    chmod 700 -- "$REPORT_DIR" || fail "Unable to secure report directory: ${REPORT_DIR}"

    local uid
    uid="$(stat -c '%u' -- "$REPORT_DIR" 2>/dev/null)" || fail "Unable to verify report directory ownership."
    [[ "$uid" == "0" ]] || fail "Report directory must be owned by root: ${REPORT_DIR}"
}

report_file_for_mode() {
    local run_mode="$1"
    case "$run_mode" in
        disk|ssl|service) printf '%s-%s.log\n' "$REPORT_FILE_PREFIX" "$run_mode" ;;
        *) fail "Internal error: invalid report mode '$run_mode'." ;;
    esac
}

main_mode() {
    local run_mode="$1"
    print_header "$run_mode"

    case "$run_mode" in
        disk) monitor_disk ;;
        ssl) monitor_ssl ;;
        service) monitor_service ;;
        *) fail "Internal error: unsupported report mode '$run_mode'." ;;
    esac
}

run_mode_with_report() {
    local run_mode="$1"
    local report_file tmp_report exit_code completion_ts

    report_file="$(report_file_for_mode "$run_mode")"
    [[ ! -d "$report_file" ]] || fail "Report path is a directory: ${report_file}"
    [[ -L "$report_file" ]] && fail "Refusing to replace symlinked report path: ${report_file}"

    tmp_report="$(mktemp --tmpdir="$REPORT_DIR" ".${run_mode}.report.XXXXXXXXXX")" || fail "Unable to create temporary report file."
    chmod 600 -- "$tmp_report" || fail "Unable to secure temporary report file."

    main_mode "$run_mode" 2>&1 | tee "$tmp_report"
    exit_code=${PIPESTATUS[0]}

    completion_ts="$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf '\nReport completed: %s\nExit code: %d\n' "$completion_ts" "$exit_code" | tee -a "$tmp_report"

    if [[ -L "$report_file" ]]; then
        printf 'ERROR: Refusing to replace symlinked report path: %s\n' "$report_file" >&2
        return 2
    fi

    mv -f -- "$tmp_report" "$report_file" || {
        printf 'ERROR: Unable to install report file: %s\n' "$report_file" >&2
        return 2
    }

    chmod 600 -- "$report_file" || exit_code=2
    printf 'Report saved: %s\n' "$report_file" >&2
    return "$exit_code"
}

run_with_report() {
    local mode rc exit_code=0

    validate_args "$@"
    require_root
    require_cmd id date hostname nice ionice awk stat mkdir chmod mv mktemp tee

    if [[ "$MODE" == "all" || "$MODE" == "disk" ]]; then
        require_cmd find sort head
    fi
    if [[ "$MODE" == "all" || "$MODE" == "ssl" ]]; then
        require_cmd openssl timeout
    fi
    if [[ "$MODE" == "all" || "$MODE" == "service" ]]; then
        require_cmd systemctl
    fi

    PANEL="$(detect_panel)"
    prepare_report_dir

    if [[ "$MODE" == "all" ]]; then
        for mode in disk ssl service; do
            run_mode_with_report "$mode"
            rc=$?
            (( rc != 0 )) && exit_code=1
            printf '\n'
        done
    else
        run_mode_with_report "$MODE"
        exit_code=$?
    fi

    return "$exit_code"
}

run_with_report "$@"
exit $?
