#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  api-recon-arjun.sh -d api.example.com [-U urls.txt|-U -] [-H "Header: Value"]... [--methods GET,JSON,POST,XML]
                     [-t threads] [-r rate_limit] [-o outdir] [--only-arjun|--only-recon]

Examples:
  # Use your URL list + recon on api.example.com, with auth header
  ./api-recon-arjun.sh -d api.example.com -U urls.txt -H "Authorization: Bearer <token>"

  # Use only your URL list (no recon)
  ./api-recon-arjun.sh -U urls.txt --only-arjun

  # Pipe URLs via STDIN and still do recon per host extracted from the list
  cat urls.txt | ./api-recon-arjun.sh -U - --methods GET,JSON -t 10

Options:
  -d DOMAIN             Base domain/host to recon (optional if -U given; script will derive hosts from URLs)
  -U FILE|'-'           File with URLs (one per line), or '-' to read from STDIN
  -H "Header: Value"    Repeatable; added to recon tools and Arjun (auth, content-type, etc.)
  -t N                  Threads/concurrency for tools (default: 10)
  -r N                  Arjun --rate-limit (req/s) (default: 5)
  -o DIR                Output directory (default: out-<domain or first-host>)
  --methods LIST        Comma-separated Arjun modes among: GET,JSON,POST,XML (default: GET,JSON)
  --only-arjun          Skip recon; process only provided URLs
  --only-recon          Do recon/merge, but skip Arjun fuzzing
USAGE
  exit 1
}

# ---------- Parse args ----------
TARGET=""
URLS_FILE=""
THREADS=10
RL=5
OUT=""
ONLY_ARJUN=0
ONLY_RECON=0
METHODS="GET,JSON"
HDRS=()

while (( "$#" )); do
  case "$1" in
    -d) TARGET="$2"; shift 2 ;;
    -U) URLS_FILE="$2"; shift 2 ;;
    -H) HDRS+=("$2"); shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -r) RL="$2"; shift 2 ;;
    -o) OUT="$2"; shift 2 ;;
    --methods) METHODS="$2"; shift 2 ;;
    --only-arjun) ONLY_ARJUN=1; shift ;;
    --only-recon) ONLY_RECON=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ -z "${TARGET}${URLS_FILE}" ]]; then
  echo "[!] Provide at least -d <domain> or -U <urls-file|->"; usage
fi
# ---------- Setup ----------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Decide OUT directory
if [[ -z "$OUT" ]]; then
  if [[ -n "$TARGET" ]]; then OUT="out-$TARGET"
  elif [[ -n "$URLS_FILE" ]]; then OUT="out-urls"
  else OUT="out-run"
  fi
fi
mkdir -p "$OUT" "$OUT/arjun-json"

# Build header arrays for tools that support -H
KATANA_HDRS=(); KR_HDRS=(); HTTPX_HDRS=()
for h in "${HDRS[@]}"; do
  KATANA_HDRS+=(-H "$h")
  KR_HDRS+=(-H "$h")
  HTTPX_HDRS+=(-H "$h")
done
# Prepare Arjun headers file (newline-separated if provided)
ARJUN_HDRS=()
if ((${#HDRS[@]})); then
  ARJUN_HEADERS_FILE="$OUT/arjun-headers.txt"
  printf "%s\n" "${HDRS[@]}" > "$ARJUN_HEADERS_FILE"
  ARJUN_HDRS=(--headers "$(cat "$ARJUN_HEADERS_FILE")")
fi

# ---------- Collect user URLs (optional) ----------
USER_URLS="$TMP/user-urls.txt"
if [[ -n "$URLS_FILE" ]]; then
  if [[ "$URLS_FILE" == "-" ]]; then
    cat - > "$USER_URLS" || true
  else
    cat "$URLS_FILE" > "$USER_URLS"
  fi
fi

# Normalize URLs (remove spaces, comments)
sed -i -E 's/[[:space:]]+$//; /^\s*#/d; /^\s*$/d' "$USER_URLS" 2>/dev/null || true

# Derive hosts (used for recon when -d missing)
DERIVED_HOSTS="$TMP/hosts.txt"
if [[ -s "$USER_URLS" ]]; then
  sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s/:.*$//' "$USER_URLS" \
    | sed -E 's/^\.*//' | sort -u > "$DERIVED_HOSTS"
fi

# Final recon host list
HOSTS="$TMP/recon-hosts.txt"
if [[ -n "$TARGET" ]]; then
  printf "%s\n" "$TARGET" > "$HOSTS"
elif [[ -s "$DERIVED_HOSTS" ]]; then
  cat "$DERIVED_HOSTS" > "$HOSTS"
fi

# ---------- Recon phase ----------
ALL_FOUND="$TMP/all-found.txt"
: > "$ALL_FOUND"

if (( ONLY_ARJUN == 0 )); then
  if [[ ! -s "$HOSTS" ]]; then
    echo "[*] No recon hosts resolved; skipping recon."
  else
    while IFS= read -r host; do
      echo "[*] Recon on $host"

      # 1) Archives: gau + waybackurls
      printf "%s\n" "$host" | gau --subs --threads "$THREADS" | tee -a "$ALL_FOUND" >/dev/null
      printf "%s\n" "$host" | waybackurls | tee -a "$ALL_FOUND" >/dev/null

      # 2) Crawler: katana (JS-aware, known files)
      katana -u "https://$host" -jc -kf all -d 3 -timeout 10 -o "$TMP/katana-$host.txt" "${KATANA_HDRS[@]}"
      cat "$TMP/katana-$host.txt" >> "$ALL_FOUND"

      # 3) JS mining: subjs -> LinkFinder
      cat "$ALL_FOUND" | sort -u | subjs | tee "$TMP/js-$host.txt" >/dev/null
      python3 -m linkfinder -i "$TMP/js-$host.txt" -o cli | tee -a "$ALL_FOUND" >/dev/null

      # 4) API route brute-force: Kiterunner (small routes first)
      KITE=""
      for cand in  github_tools/kiterunner/routes-small.kite ; do
        [[ -f "$cand" ]] && KITE="$cand" && break
      done
      if [[ -n "$KITE" ]]; then
        kr scan "https://$host" -w "$KITE" -j "$THREADS" -x 20 "${KR_HDRS[@]}" \
          | tee "$TMP/kr-$host.txt" >/dev/null
        cat "$TMP/kr-$host.txt" >> "$ALL_FOUND"
      else
        echo "[!] Kiterunner wordlist not found (kiterunner/routes-small.*); skipping KR for $host"
      fi

    done < "$HOSTS"
  fi
fi

# ---------- Merge user URLs + recon URLs ----------
MERGED="$TMP/merged.txt"
cat "$ALL_FOUND" "$USER_URLS" 2>/dev/null | sed 's/#.*$//' | sed '/^\s*$/d' | sort -u > "$MERGED"

# Normalize for probing (strip query/fragments for liveness probe)
ENDPOINTS_RAW="$OUT/endpoints-raw.txt"
cat "$MERGED" | sed 's/#.*$//; s/\?.*$//' | sort -u > "$ENDPOINTS_RAW"

# Probe with httpx (keep interesting status)
LIVE="$OUT/endpoints-live.txt"
if (( ONLY_RECON == 1 )); then
  cp "$ENDPOINTS_RAW" "$LIVE"
else
  echo "[*] Probing endpoints for liveness with httpx..."
  cat "$ENDPOINTS_RAW" | httpx -silent -status-code -mc 200,401,403,405 "${HTTPX_HDRS[@]}" -o "$LIVE"
fi

# ---------- Arjun phase ----------
if (( ONLY_RECON == 0 )); then
  echo "[*] Running Arjun on live endpoints..."
  IFS=',' read -r -a MODES <<< "$METHODS"

  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    stem=$(printf "%s" "$url" | md5sum | cut -d' ' -f1)

    for m in "${MODES[@]}"; do
      mode=$(echo "$m" | tr '[:lower:]' '[:upper:]')
      case "$mode" in
        GET)
          echo "  [+] Arjun GET -> $url"
          arjun -u "$url" -t "$THREADS" --rate-limit "$RL" -oJ "$OUT/arjun-json/${stem}-GET.json" "${ARJUN_HDRS[@]}" || true
          ;;
        JSON)
          echo "  [+] Arjun JSON -> $url"
          arjun -u "$url" -m JSON --include "{}" -t "$THREADS" --rate-limit "$RL" -oJ "$OUT/arjun-json/${stem}-JSON.json" "${ARJUN_HDRS[@]}" || true
          ;;
        POST)
          echo "  [+] Arjun POST(form) -> $url"
          arjun -u "$url" -m POST -t "$THREADS" --rate-limit "$RL" -oJ "$OUT/arjun-json/${stem}-POST.json" "${ARJUN_HDRS[@]}" || true
          ;;
        XML)
          echo "  [+] Arjun XML -> $url"
          arjun -u "$url" -m XML  -t "$THREADS" --rate-limit "$RL" -oJ "$OUT/arjun-json/${stem}-XML.json"  "${ARJUN_HDRS[@]}" || true
          ;;
        *)
          echo "[!] Unknown Arjun mode: $mode (skipping)"
          ;;
      esac
    done
  done < "$LIVE"
fi

echo
echo "[*] Complete. Artifacts in: $OUT/"
echo "    - endpoints-raw.txt     (merged candidates before probing)"
echo "    - endpoints-live.txt    (final probed endpoints)"
echo "    - arjun-json/*.json     (per-endpoint parameter findings)"
