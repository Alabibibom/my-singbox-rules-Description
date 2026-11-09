
#!/usr/bin/env bash
set -Eeuo pipefail

# Use the sing-box version matching the target client series.
SING_BOX_VERSION="1.14.4"
SING_BOX="${SING_BOX_BIN:-sing-box}"

OUT_DIR="public/rules"
mkdir -p "$OUT_DIR"

# Temporary files live on the same filesystem as the final SRS files.
TMP_DIR="$(mktemp -d "${OUT_DIR}/.build-XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

# Upstream DNS rule sources.
declare -A SOURCES=(
  ["geosite-hagezi-pro"]="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"
  ["geosite-chn-adrules"]="https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt"
  ["geosite-dandelion-sprout-anti-malware"]="https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuardHome.txt"
)

# Make sure the compiler is the intended sing-box version.
if ! command -v "$SING_BOX" >/dev/null 2>&1; then
  echo "ERROR: sing-box executable not found"
  exit 1
fi

if ! "$SING_BOX" version | grep -qF "$SING_BOX_VERSION"; then
  echo "ERROR: expected sing-box $SING_BOX_VERSION"
  "$SING_BOX" version || true
  exit 1
fi

for name in "${!SOURCES[@]}"; do
  url="${SOURCES[$name]}"
  input="${TMP_DIR}/${name}.txt"
  output="${TMP_DIR}/${name}.srs"
  final="${OUT_DIR}/${name}.srs"

  echo "======================================"
  echo "Building: ${name}"
  echo "Source: ${url}"

  # Download with retries.
  curl -fLsS --compressed \
    --retry 3 \
    --retry-delay 3 \
    --connect-timeout 15 \
    --max-time 300 \
    -A "sing-box-rule-builder" \
    -o "$input" "$url"

  # Reject empty, suspiciously small, or HTML responses.
  size="$(wc -c < "$input")"
  if [ "$size" -lt 256 ]; then
    echo "ERROR: source file is too small: ${size} bytes"
    exit 1
  fi

  if head -c 512 "$input" | grep -qiE '<(html|!doctype)'; then
    echo "ERROR: upstream returned HTML instead of a rule list"
    exit 1
  fi

  # Convert using sing-box's built-in AdGuard parser.
  "$SING_BOX" rule-set convert \
    --type adguard \
    --output "$output" \
    "$input"

  # Never replace a previous working file with an empty result.
  if [ ! -s "$output" ] || [ "$(wc -c < "$output")" -lt 100 ]; then
    echo "ERROR: generated SRS is empty or suspiciously small"
    exit 1
  fi

  # Atomic replacement: the previous SRS remains if conversion fails.
  mv -f "$output" "$final"

  echo "SUCCESS: ${final}"
  sha256sum "$final"
done


# ======================================
# Build FireHOL Level 3 IP rule-set
# ======================================

echo "======================================"
echo "Building: firehol-level3"

IP_SOURCE="${TMP_DIR}/firehol-level3.netset"
IP_JSON="${TMP_DIR}/firehol-level3.json"
IP_OUTPUT="${TMP_DIR}/geoip-firehol-level3.srs"
IP_FINAL="${OUT_DIR}/geoip-firehol-level3.srs"

# Download official FireHOL IPv4 blocklist
curl -fLsS --compressed --retry 3 \
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset" \
  -o "$IP_SOURCE"

# Convert IP/CIDR entries into sing-box source format
python3 - "$IP_SOURCE" "$IP_JSON" <<'PY'
import sys
import json
import ipaddress

source, output = sys.argv[1:3]
networks = []

with open(source, encoding="utf-8") as f:
    for line in f:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
            if network.version == 4:
                networks.append(str(network))
        except ValueError:
            continue

if not networks:
    raise SystemExit("ERROR: no valid IPv4 entries found")

with open(output, "w", encoding="utf-8") as f:
    json.dump({
        "version": 5,
        "rules": [{"ip_cidr": networks}]
    }, f)

print(f"Valid IPv4/CIDR entries: {len(networks)}")
PY

# Compile using sing-box official compiler
"$SING_BOX" rule-set compile \
  --output "$IP_OUTPUT" \
  "$IP_JSON"

if [ ! -s "$IP_OUTPUT" ] || [ "$(wc -c < "$IP_OUTPUT")" -lt 100 ]; then
  echo "ERROR: FireHOL SRS is empty or suspiciously small"
  exit 1
fi

mv -f "$IP_OUTPUT" "$IP_FINAL"

echo "SUCCESS: ${IP_FINAL}"
sha256sum "$IP_FINAL"

# Write a checksum manifest after all four builds.
(
  cd "$OUT_DIR"
  sha256sum \
    geosite-hagezi-pro.srs \
    geosite-chn-adrules.srs \
    geosite-dandelion-sprout-anti-malware.srs \
    geoip-firehol-level3.srs
) > "${TMP_DIR}/SHA256SUMS"

mv -f "${TMP_DIR}/SHA256SUMS" "${OUT_DIR}/SHA256SUMS"

echo "======================================"
echo "All rule sets built successfully."
