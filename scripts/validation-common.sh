#!/usr/bin/env bash
# Common remote validation commands. Java reads this file as command blocks; it does not execute it locally.
# Format: ##CKNN # short description, followed by command line(s) up to the next ##CKNN marker.
# Keep commands simple and return raw output. Parsing and grouping belongs in Java.

##CK01 # Probe /etc/issue for BIG-IP detection
cat /etc/issue 2>/dev/null || true

##CK02 # Read Linux hostname
uname -n 2>/dev/null || true

##CK04 # Read operating system release metadata
cat /etc/os-release 2>/dev/null || true

##CK05 # Read kernel and platform details
uname -a 2>/dev/null || true

##CK06 # Read system issue banner
cat /etc/issue 2>/dev/null || true

##CK09 # Read system uptime
uptime -p 2>/dev/null || uptime 2>/dev/null || echo unknown

##CK10 # Read raw memory counters
cat /proc/meminfo 2>/dev/null || true

##CK11 # Count available CPU cores
getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1

##CK12 # Read 1m 5m 15m load averages
cat /proc/loadavg 2>/dev/null || echo '0 0 0'

##CK13 # Read disk usage for all mounts or configured mount paths
df -Pk ${DISK_PATHS} 2>/dev/null || true

##CK14 # List active TCP and UDP connections
netstat -natup 2>/dev/null | grep -i ESTABLISHED || true

##CK15 # Read current conntrack connection count
cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || true

##CK16 # Read maximum allowed conntrack connections
cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0

##CK18 # List process command names
ps -eo comm= 2>/dev/null || true

##CK19 # List processes with CPU memory RSS shared memory and command
ps -eo pid=,pcpu=,pmem=,rss=,share=,comm= 2>/dev/null || ps aux 2>/dev/null || true

##CK20 # Read network interface byte counters
cat /proc/net/dev 2>/dev/null || true

##CK21 # List IPv4 and IPv6 interface addresses
ip -o addr show 2>/dev/null || true

##CK22 # List listening sockets with process details
netstat -natup 2>/dev/null | grep -i LISTEN || true

##CK23 # Fallback listener list through netstat
netstat -natup 2>/dev/null | grep -i LISTEN || true

##CK24 # Read service name to port mappings
cat /etc/services 2>/dev/null || true

##CK25 # Tail common system and F5 log files
tail -n ${LOG_LOOKBACK_LINES} /var/log/ltm /var/log/audit /var/log/kern.log /var/log/messages /var/log/syslog 2>/dev/null || true

##CK26 # Read a short vmstat CPU and memory sample if vmstat is installed
vmstat 1 2 2>/dev/null | tail -n 1 || true

##CK29 # Read local users and last login timestamps
cat /etc/passwd 2>/dev/null; echo __LASTLOG__; lastlog 2>/dev/null || true

##CK31 # Test outbound TCP or UDP connectivity to one configured host and port
host=${HOST}
port=${PORT}
protocol=$(printf '%s' ${PROTOCOL} | tr '[:lower:]' '[:upper:]')
check_name=${CHECK_NAME}
timeout_seconds=${TIMEOUT_SECONDS}
status=1
output=""
resolved_ip=$(getent ahosts "${host}" 2>/dev/null | awk '{print $1; exit}')
if [ -z "${resolved_ip}" ]; then
  resolved_ip=$(getent hosts "${host}" 2>/dev/null | awk '{print $1; exit}')
fi
if [ -z "${resolved_ip}" ]; then
  resolved_ip="${host}"
fi
if [ "${protocol}" = "TCP" ]; then
  if command -v nc >/dev/null 2>&1; then
    if command -v timeout >/dev/null 2>&1; then
      output=$(printf '' | timeout "${timeout_seconds}" nc -v -w "${timeout_seconds}" "${host}" "${port}" 2>&1)
    else
      output=$(printf '' | nc -v -w "${timeout_seconds}" "${host}" "${port}" 2>&1)
    fi
    status=$?
  else
    if command -v timeout >/dev/null 2>&1; then
      output=$(timeout "${timeout_seconds}" bash -c "</dev/tcp/${host}/${port}" 2>&1)
    else
      output=$(bash -c "</dev/tcp/${host}/${port}" 2>&1)
    fi
    status=$?
  fi
elif [ "${protocol}" = "UDP" ]; then
  if command -v nc >/dev/null 2>&1; then
    dns_received_bytes=0
    radius_received_bytes=0
    dns_probe_enabled=0
    check_name_lower=$(printf '%s' "${check_name}" | tr '[:upper:]' '[:lower:]')
    if [ "${port}" = "53" ] || printf '%s' "${check_name_lower}" | grep -q 'dns'; then
      dns_probe_enabled=1
    fi
    if [ "${dns_probe_enabled}" -eq 1 ]; then
      if command -v timeout >/dev/null 2>&1; then
        dns_received_bytes=$(printf '\022\064\001\000\000\001\000\000\000\000\000\000\000\000\001\000\001' | timeout "${timeout_seconds}" nc -u -w "${timeout_seconds}" "${host}" "${port}" 2>/dev/null | wc -c | awk '{print $1}')
      else
        dns_received_bytes=$(printf '\022\064\001\000\000\001\000\000\000\000\000\000\000\000\001\000\001' | nc -u -w "${timeout_seconds}" "${host}" "${port}" 2>/dev/null | wc -c | awk '{print $1}')
      fi
    fi
    if command -v timeout >/dev/null 2>&1; then
      radius_received_bytes=$(printf '\001\001\000\024\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000' | timeout "${timeout_seconds}" nc -u -w "${timeout_seconds}" "${host}" "${port}" 2>/dev/null | wc -c | awk '{print $1}')
    else
      radius_received_bytes=$(printf '\001\001\000\024\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000' | nc -u -w "${timeout_seconds}" "${host}" "${port}" 2>/dev/null | wc -c | awk '{print $1}')
    fi
    if [ -z "${dns_received_bytes}" ]; then dns_received_bytes=0; fi
    if [ -z "${radius_received_bytes}" ]; then radius_received_bytes=0; fi
    if [ "${dns_received_bytes}" -gt 0 ] 2>/dev/null || [ "${radius_received_bytes}" -gt 0 ] 2>/dev/null; then
      output="UDP_DNS_PROBE_ENABLED=${dns_probe_enabled} UDP_DNS_BYTES_SENT=$([ "${dns_probe_enabled}" -eq 1 ] && echo 17 || echo 0) UDP_DNS_BYTES_RECEIVED=${dns_received_bytes} UDP_RADIUS_BYTES_SENT=20 UDP_RADIUS_BYTES_RECEIVED=${radius_received_bytes} Response bytes were received from at least one UDP probe."
      status=0
    else
      output="UDP_DNS_PROBE_ENABLED=${dns_probe_enabled} UDP_DNS_BYTES_SENT=$([ "${dns_probe_enabled}" -eq 1 ] && echo 17 || echo 0) UDP_DNS_BYTES_RECEIVED=${dns_received_bytes} UDP_RADIUS_BYTES_SENT=20 UDP_RADIUS_BYTES_RECEIVED=${radius_received_bytes} No response bytes were received; UDP packet send alone does not prove service reachability."
      status=3
    fi
  else
    output="UDP_DNS_BYTES_SENT=0 UDP_DNS_BYTES_RECEIVED=0 UDP_RADIUS_BYTES_SENT=0 UDP_RADIUS_BYTES_RECEIVED=0 nc is not available, so UDP response-byte probing could not be attempted."
    status=3
  fi
else
  output="Unsupported protocol: ${protocol}"
  status=2
fi
if [ "${status}" -eq 3 ]; then
  echo "OUTBOUND_CHECK_UNKNOWN"
elif [ "${status}" -eq 0 ]; then
  echo "OUTBOUND_CHECK_PASS"
else
  echo "OUTBOUND_CHECK_FAIL"
fi
printf 'RESOLVED_IP=%s\n' "${resolved_ip}"
printf '%s\n' "${output}"

##CK32 # Read recent SSH login users from wtmp and auth logs
last -w -F 2>/dev/null | grep -v '^$' | grep -v 'wtmp begins' | head -n 50 || true
echo __SSH_AUTH_LOGS__
grep -hEi 'sshd.*(Accepted|Failed|Invalid user|session opened|session closed)' /var/log/secure* /var/log/auth.log* /var/log/messages* /var/log/audit* 2>/dev/null | tail -n 200 || true

##CK34 # Probe TLS certificate from one host and port
host=${HOST}
port=${PORT}
timeout_seconds=${TIMEOUT_SECONDS}
resolved_ip=$(getent ahosts "${host}" 2>/dev/null | awk '{print $1; exit}')
if [ -z "${resolved_ip}" ]; then
  resolved_ip=$(getent hosts "${host}" 2>/dev/null | awk '{print $1; exit}')
fi
if [ -z "${resolved_ip}" ]; then
  resolved_ip="${host}"
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "OUTBOUND_CHECK_UNKNOWN"
  printf 'RESOLVED_IP=%s\n' "${resolved_ip}"
  echo "TLS_CERT_PRESENT=0 TLS_ERROR=openssl not available"
elif command -v timeout >/dev/null 2>&1; then
  tls_output=$(timeout "${timeout_seconds}" openssl s_client -connect "${host}:${port}" -servername "${host}" -showcerts </dev/null 2>&1)
else
  tls_output=$(openssl s_client -connect "${host}:${port}" -servername "${host}" -showcerts </dev/null 2>&1)
fi
if command -v openssl >/dev/null 2>&1; then
  cert_count=$(printf '%s\n' "${tls_output}" | grep -c -- '-----BEGIN CERTIFICATE-----')
  leaf_cert=$(printf '%s\n' "${tls_output}" | awk '
    /-----BEGIN CERTIFICATE-----/ { in_cert=1 }
    in_cert { print }
    /-----END CERTIFICATE-----/ { exit }
  ')
  if [ "${cert_count}" -gt 0 ] 2>/dev/null && [ -n "${leaf_cert}" ]; then
    cert_text=$(printf '%s\n' "${leaf_cert}" | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 2>/dev/null)
    subject=$(printf '%s\n' "${cert_text}" | awk -F= '/^subject=/{sub(/^subject=/,""); print; exit}')
    issuer=$(printf '%s\n' "${cert_text}" | awk -F= '/^issuer=/{sub(/^issuer=/,""); print; exit}')
    not_before=$(printf '%s\n' "${cert_text}" | awk -F= '/^notBefore=/{sub(/^notBefore=/,""); print; exit}')
    not_after=$(printf '%s\n' "${cert_text}" | awk -F= '/^notAfter=/{sub(/^notAfter=/,""); print; exit}')
    fingerprint=$(printf '%s\n' "${cert_text}" | awk -F= 'tolower($0) ~ /^sha256 fingerprint=/{sub(/^[^=]*=/,"SHA256/"); print; exit}')
    common_name=$(printf '%s\n' "${subject}" | sed -n 's/.*CN[ =]*\([^,/]*\).*/\1/p' | head -n 1)
    echo "OUTBOUND_CHECK_PASS"
    printf 'RESOLVED_IP=%s\n' "${resolved_ip}"
    printf 'TLS_CERT_PRESENT=1; TLS_CHAIN_CERTS=%s; TLS_CERT_SUBJECT=%s; TLS_CERT_CN=%s; TLS_CERT_ISSUER=%s; TLS_CERT_NOT_BEFORE=%s; TLS_CERT_NOT_AFTER=%s' "${cert_count}" "${subject}" "${common_name}" "${issuer}" "${not_before}" "${not_after}"
    if [ -n "${fingerprint}" ]; then
      printf '; TLS_CERT_FINGERPRINT=%s' "${fingerprint}"
    fi
    tmp_dir=$(mktemp -d 2>/dev/null || true)
    if [ -n "${tmp_dir}" ]; then
      printf '%s\n' "${tls_output}" | awk -v dir="${tmp_dir}" '
        /-----BEGIN CERTIFICATE-----/ { idx++; file=sprintf("%s/cert_%03d.pem", dir, idx); in_cert=1 }
        in_cert { print > file }
        /-----END CERTIFICATE-----/ { close(file); in_cert=0 }
      '
      chain_index=1
      for cert_file in "${tmp_dir}"/cert_*.pem; do
        [ -f "${cert_file}" ] || continue
        if [ "${chain_index}" -gt 1 ]; then
          chain_text=$(openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 -in "${cert_file}" 2>/dev/null)
          chain_subject=$(printf '%s\n' "${chain_text}" | awk -F= '/^subject=/{sub(/^subject=/,""); print; exit}')
          chain_issuer=$(printf '%s\n' "${chain_text}" | awk -F= '/^issuer=/{sub(/^issuer=/,""); print; exit}')
          chain_not_before=$(printf '%s\n' "${chain_text}" | awk -F= '/^notBefore=/{sub(/^notBefore=/,""); print; exit}')
          chain_not_after=$(printf '%s\n' "${chain_text}" | awk -F= '/^notAfter=/{sub(/^notAfter=/,""); print; exit}')
          chain_fingerprint=$(printf '%s\n' "${chain_text}" | awk -F= 'tolower($0) ~ /^sha256 fingerprint=/{sub(/^[^=]*=/,"SHA256/"); print; exit}')
          printf '; TLS_CHAIN_%s_SUBJECT=%s; TLS_CHAIN_%s_ISSUER=%s; TLS_CHAIN_%s_NOT_BEFORE=%s; TLS_CHAIN_%s_NOT_AFTER=%s' "${chain_index}" "${chain_subject}" "${chain_index}" "${chain_issuer}" "${chain_index}" "${chain_not_before}" "${chain_index}" "${chain_not_after}"
          if [ -n "${chain_fingerprint}" ]; then
            printf '; TLS_CHAIN_%s_FINGERPRINT=%s' "${chain_index}" "${chain_fingerprint}"
          fi
        fi
        chain_index=$((chain_index + 1))
      done
      rm -rf "${tmp_dir}"
    fi
    printf '\n'
  else
    echo "OUTBOUND_CHECK_UNKNOWN"
    printf 'RESOLVED_IP=%s\n' "${resolved_ip}"
    echo "TLS_CERT_PRESENT=0; TLS_ERROR=no certificate returned"
  fi
fi
