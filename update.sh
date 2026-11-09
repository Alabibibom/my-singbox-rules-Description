
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
  ["hagezi-pro"]="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"
  ["adrules-cn"]="https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt"
  ["anti-ad"]="https://anti-ad.net/adguard.txt"
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

# Write a checksum manifest after all three builds succeed.
(
  cd "$OUT_DIR"
  sha256sum hagezi-pro.srs adrules-cn.srs anti-ad.srs
) > "${TMP_DIR}/SHA256SUMS"

mv -f "${TMP_DIR}/SHA256SUMS" "${OUT_DIR}/SHA256SUMS"

echo "======================================"
echo "All rule sets built successfully."
