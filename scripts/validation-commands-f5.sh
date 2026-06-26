#!/usr/bin/env bash
# F5/BIG-IP-specific remote validation commands. Java reads this file as command blocks.

##CK03 # Read F5 hostname through tmsh
tmsh list sys global-settings hostname 2>/dev/null || true

##CK07 # Check whether tmsh exists
command -v tmsh 2>/dev/null || true

##CK08 # Read F5 product and version files
cat /VERSION /etc/product 2>/dev/null || true

##CK17 # Read F5 service status through tmsh
tmsh show sys service 2>/dev/null || true

##CK27 # Read F5 system performance counters through tmsh
tmsh show sys performance system 2>/dev/null || true

##CK28 # Read F5 connection performance counters through tmsh
tmsh show sys performance connections 2>/dev/null || true

##CK30 # Read F5 historical CPU and traffic RRD samples for the last 48 hours when rrdtool data exists
if command -v rrdtool >/dev/null 2>&1; then
  find /var/rrd /shared/rrd.1.2 /shared/rrd* -type f \( \
    -iname '*cpu*' -o -iname '*load*' -o -iname '*system*' -o \
    -iname '*throughput*' -o -iname '*traffic*' -o -iname '*connections*' -o \
    -iname '*bwgain*' -o -iname '*ramcache*' -o -iname '*ltmdns*' \
  \) ! -iname '*.info' 2>/dev/null | head -n 24 | while read -r rrd_file; do
    echo "__RRD_FILE__ ${rrd_file}"
    rrdtool fetch "${rrd_file}" AVERAGE -s -48h -r 3600 2>/dev/null | awk '
      NR == 1 {
        for (i=1; i<=NF; i++) {
          ds[i]=$i
        }
        next
      }
      /^[0-9]+:/ {
        ts=$1
        gsub(":", "", ts)
        for (i=2; i<=NF; i++) {
          if ($i != "-nan" && $i != "nan" && $i != "NaN") {
            v=$i + 0
            name=ds[i-1]
            if (name == "") {
              name="ds" i-1
            }
            printf "%s|%s|%.6f\n", ts, name, v
          }
        }
      }'
  done
fi

##CK33 # List F5 partitions, pools, VIPs, SSL profiles, SSL certificate file objects, and VIP stats
tmsh -q -c 'cd /; list auth partition one-line; list ltm pool recursive one-line; list ltm virtual recursive one-line; list ltm profile client-ssl recursive one-line; list ltm profile server-ssl recursive one-line; list sys file ssl-cert recursive one-line; show ltm virtual recursive' 2>/dev/null || true

##CK35 # List installed F5 crypto certificates per partition
tmsh -q -c 'cd /; list auth partition one-line' 2>/dev/null | awk '/^auth partition / { print $3 }' | while read -r partition; do
  if [ -n "${partition}" ]; then
    echo "__F5_PARTITION__ ${partition}"
    tmsh -q -c "cd /${partition}; list sys crypto cert" 2>/dev/null || true
  fi
done
tmsh -q -c 'cd /; list sys file ssl-cert recursive one-line' 2>/dev/null | while IFS= read -r cert_line; do
  echo "${cert_line}"
  cert_path=$(printf '%s\n' "${cert_line}" | awk '/^sys file ssl-cert / { print $4 }')
  cache_path=$(printf '%s\n' "${cert_line}" | sed -n 's/.* cache-path \([^ ]*\).*/\1/p')
  if [ -n "${cert_path}" ] && [ -z "${cache_path}" ]; then
    cache_path=$(tmsh -q -c "cd /; list sys file ssl-cert ${cert_path} cache-path one-line" 2>/dev/null | sed -n 's/.* cache-path \([^ ]*\).*/\1/p' | head -n 1)
  fi
  if [ -n "${cert_path}" ] && [ -n "${cache_path}" ] && command -v openssl >/dev/null 2>&1; then
    cert_dates=$(openssl x509 -noout -startdate -enddate -fingerprint -sha256 -in "${cache_path}" 2>/dev/null || true)
    not_before=$(printf '%s\n' "${cert_dates}" | awk -F= '/^notBefore=/{sub(/^notBefore=/,""); print; exit}')
    not_after=$(printf '%s\n' "${cert_dates}" | awk -F= '/^notAfter=/{sub(/^notAfter=/,""); print; exit}')
    fingerprint=$(printf '%s\n' "${cert_dates}" | awk -F= 'tolower($0) ~ /^sha256 fingerprint=/{sub(/^[^=]*=/,"SHA256/"); print; exit}')
    printf '__SSL_CERT_DATES__ %s; NOT_BEFORE=%s; NOT_AFTER=%s' "${cert_path}" "${not_before}" "${not_after}"
    if [ -n "${fingerprint}" ]; then
      printf '; FINGERPRINT=%s' "${fingerprint}"
    fi
    printf '\n'
  fi
done
