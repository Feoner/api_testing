
#!/usr/bin/env bash
set -euo pipefail


RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; NC="\033[0m"
info()    { echo -e "${BLUE}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC} $*"; }

usage() {
  cat <<'USAGE'
Usage:
  api-recon-arjun.sh -d api.example.com [-U urls.txt|-U -] [-H "Header: Value"]... [--methods GET,JSON,POST,XML]
                     [-t threads] [-r rate_limit] [-o outdir] [--only-arjun|--only-recon] [--debug]
                     [--json-summary] [--dalfox-blind URL] [--vulnapi-openapi FILE|URL] [--vulnapi-token TOKEN]
                     [--no-vulnapi] [--no-mantra] [--no-dalfox]

Examples:
  ./api_test.sh -d https://api.example.com --methods GET,POST -H "Authorization: Bearer XYZ" --json-summary
  ./api_test.sh -d api.example.com --dalfox-blind https://x.your-callback.com
USAGE
  exit 1
}


TARGET=""; URLS_FILE=""; THREADS=10; RL=5; OUT=""
ONLY_ARJUN=0; ONLY_RECON=0; METHODS="GET,JSON"; DEBUG=0; HDRS=(); JSON_SUMMARY=0
DALFOX_BLIND=""; VULNAPI_OPENAPI=""; VULNAPI_TOKEN=""
NO_VULNAPI=0; NO_MANTRA=0; NO_DALFOX=0

while (("$#")); do
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
    --debug) DEBUG=1; shift ;;
    --json-summary) JSON_SUMMARY=1; shift ;;
    --dalfox-blind) DALFOX_BLIND="$2"; shift 2 ;;
    --vulnapi-openapi) VULNAPI_OPENAPI="$2"; shift 2 ;;
    --vulnapi-token) VULNAPI_TOKEN="$2"; shift 2 ;;
    --no-vulnapi) NO_VULNAPI=1; shift ;;
    --no-mantra) NO_MANTRA=1; shift ;;
    --no-dalfox) NO_DALFOX=1; shift ;;
    -h|--help) usage ;;
    *) error "Unknown option: $1"; usage ;;
  esac
done

[[ -z "${TARGET}${URLS_FILE}" ]] && { warn "Provide -d <domain|url> or -U <urls-file|-">; usage; }
(( DEBUG == 1 )) && set -x


TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Sanitize output directory name
if [[ -z "$OUT" ]]; then
  if [[ -n "$TARGET" ]]; then OUT="out-$(echo "$TARGET" | sed 's|https\?://||; s|/|_|g')"
  elif [[ -n "$URLS_FILE" ]]; then OUT="out-urls"
  else OUT="out-run"
  fi
fi
mkdir -p "$OUT" "$OUT/arjun-json"
info "Output directory: $OUT"

# Headers for tools
KATANA_HDRS=(); KR_HDRS=(); HTTPX_HDRS=(); DALFOX_HDRS=()
for h in "${HDRS[@]}"; do
  KATANA_HDRS+=(-H "$h"); KR_HDRS+=(-H "$h"); HTTPX_HDRS+=(-H "$h"); DALFOX_HDRS+=(-H "$h")
done

# Headers file for Arjun (newline-separated)
ARJUN_HDRS=()
if ((${#HDRS[@]})); then
  ARJUN_HEADERS_FILE="$OUT/arjun-headers.txt"
  printf "%s\n" "${HDRS[@]}" > "$ARJUN_HEADERS_FILE"
  ARJUN_HDRS=(--headers "$(cat "$ARJUN_HEADERS_FILE")")
fi

USER_URLS="$TMP/user-urls.txt"; : > "$USER_URLS"
if [[ -n "$URLS_FILE" ]]; then
  [[ "$URLS_FILE" == "-" ]] && cat - > "$USER_URLS" || cat "$URLS_FILE" > "$USER_URLS"
fi
sed -i -E 's/[[:space:]]+$//; /^\s*#/d; /^\s*$/d' "$USER_URLS" 2>/dev/null || true
info "User URLs provided: $(wc -l < "$USER_URLS" 2>/dev/null || echo 0)"

DERIVED_HOSTS="$TMP/hosts.txt"; : > "$DERIVED_HOSTS"
if [[ -s "$USER_URLS" && -z "$TARGET" ]]; then
  sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s/:.*$//' "$USER_URLS" \
    | sed -E 's/^\.*//' | sort -u > "$DERIVED_HOSTS"
fi
HOSTS="$TMP/recon-hosts.txt"; : > "$HOSTS"
if [[ -n "$TARGET" ]]; then printf "%s\n" "$TARGET" > "$HOSTS"
elif [[ -s "$DERIVED_HOSTS" ]]; then cat "$DERIVED_HOSTS" > "$HOSTS"; fi
info "Recon hosts: $(wc -l < "$HOSTS" 2>/dev/null || echo 0)"

ALL_FOUND="$TMP/all-found.txt"; : > "$ALL_FOUND"
ALL_JS="$OUT/js-urls.txt"; : > "$ALL_JS"

if (( ONLY_ARJUN == 0 )) && [[ -s "$HOSTS" ]]; then
  info "Starting recon phase (parallelized)..."

  export TMP ALL_FOUND THREADS HDRS KATANA_HDRS KR_HDRS
  export -f success warn error info

  cat "$HOSTS" | xargs -I{} -P "$THREADS" bash -c '
    host_input="{}"
    [[ -z "$host_input" ]] && exit 0
    # Normalize to domain (strip scheme, path, port)
    host_domain=$(echo "$host_input" | sed "s#^[a-zA-Z]*://##; s#/.*$##; s/:.*$//")
    safe_host=$(echo "$host_domain" | sed "s|/|_|g")
    echo; info "Recon on $host_domain"

    # 1) Archives
    printf "%s\n" "$host_domain" | gau --subs --threads "$THREADS" >> "$ALL_FOUND" 2>/dev/null || true
    printf "%s\n" "$host_domain" | waybackurls >> "$ALL_FOUND" 2>/dev/null || true
    success "After archives: $(wc -l < "$ALL_FOUND") lines"

    # 2) Katana crawler (JS-aware)
    if command -v katana >/dev/null 2>&1; then
      katana -u "https://$host_domain" -jc -kf all -d 3 -timeout 10 -o "$TMP/katana-$safe_host.txt" "${KATANA_HDRS[@]}" || true
      cat "$TMP/katana-$safe_host.txt" >> "$ALL_FOUND" 2>/dev/null || true
      success "After katana: $(wc -l < "$ALL_FOUND") lines"
    else
      warn "Katana not found; skipping"
    fi

    # 3) JS mining (subjs -> LinkFinder)
    js_file="$TMP/js-$safe_host.txt"
    sort -u "$ALL_FOUND" | subjs > "$js_file" || true
    cat "$js_file" >> "'"$ALL_JS"'" 2>/dev/null || true
    if python3 - <<PY >/dev/null 2>&1
import importlib.util, sys
sys.exit(0 if importlib.util.find_spec("linkfinder") else 1)
PY
    then
      python3 -m linkfinder -i "$js_file" -o cli >> "$ALL_FOUND" 2>/dev/null || true
      success "After LinkFinder: $(wc -l < "$ALL_FOUND") lines"
    else
      warn "LinkFinder not found; skipping JS parsing"
    fi

    # 4) Kiterunner (URL-only extraction)
    KITE="github_tools/kiterunner/routes-small.kite"
    if [[ -f "$KITE" ]]; then
      CURL_HDRS=(); for h in "${HDRS[@]}"; do CURL_HDRS+=(-H "$h"); done
      BASE_URL="https://$host_domain/this_should_not_exist_$(date +%s)"
      BASELEN=$(curl -skL "${CURL_HDRS[@]}" "$BASE_URL" | wc -c | tr -d " ")
      KR_IGNORE=()
      [[ "$BASELEN" =~ ^[0-9]+$ && "$BASELEN" -gt 0 ]] && KR_IGNORE=(--ignore-length "$BASELEN")
      KR_OUT="$TMP/kr-$safe_host.txt"
      kr scan "https://$host_domain" -w "$KITE" -j "$THREADS" -x 20 "${KR_HDRS[@]}" "${KR_IGNORE[@]}" \
        --output text --quiet > "$KR_OUT" || true
      grep -Eo "https?://[^ ]+" "$KR_OUT" | sort -u >> "$ALL_FOUND" || true
      success "After Kiterunner: $(wc -l < "$ALL_FOUND") lines"
    else
      warn "Kiterunner wordlist not found; skipping"
    fi
  '
else
  info "Skipping recon phase"
fi

MERGED="$TMP/merged.txt"
cat "$ALL_FOUND" "$USER_URLS" 2>/dev/null | sed "s/#.*$//" | sed "/^\s*$/d" | sort -u > "$MERGED"
info "Merged candidates: $(wc -l < "$MERGED" 2>/dev/null || echo 0)"

ENDPOINTS_RAW="$OUT/endpoints-raw.txt"
grep -E "^https?://.+" "$MERGED" | sort -u > "$ENDPOINTS_RAW"
info "endpoints-raw.txt: $(wc -l < "$ENDPOINTS_RAW" 2>/dev/null || echo 0)"

LIVE="$OUT/endpoints-live.txt"
if (( ONLY_RECON == 1 )); then
  cp "$ENDPOINTS_RAW" "$LIVE"
else
  info "Probing endpoints for liveness with httpx..."
  MATCH_CODES="200,201,202,204,301,302,307,308,401,403,405"
  if command -v httpx >/dev/null 2>&1; then
    cat "$ENDPOINTS_RAW" | httpx -silent -status-code -mc "$MATCH_CODES" "${HTTPX_HDRS[@]}" -o "$LIVE"
  else
    warn "httpx not found; copying raw endpoints to live list"
    cp "$ENDPOINTS_RAW" "$LIVE"
  fi
fi
info "endpoints-live.txt: $(wc -l < "$LIVE" 2>/dev/null || echo 0)"


ARJUN_COUNT=0; declare -A MODE_COUNTS
if (( ONLY_RECON == 0 )); then
  [[ ! -s "$LIVE" && -s "$ENDPOINTS_RAW" ]] && { warn "No live endpoints; falling back to raw list"; cp "$ENDPOINTS_RAW" "$LIVE"; }
  info "Running Arjun on endpoints..."
  IFS="," read -r -a MODES <<< "$METHODS"
  for m in "${MODES[@]}"; do MODE_COUNTS["$m"]=0; done

  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    stem=$(printf "%s" "$url" | md5sum | cut -d" " -f1)
    for m in "${MODES[@]}"; do
      mode=$(echo "$m" | tr "[:lower:]" "[:upper:]")
      case "$mode" in
        GET)
          success "Arjun GET -> $url"
          arjun -u "$url" -t "$THREADS" --rate-limit "$RL" -oJ "$OUT/arjun-json/${stem}-GET.json" "${ARJUN_HDRS[@]}" || true
          ((ARJUN_COUNT++)); ((MODE_COUNTS["$m"]++))
          ;;
        JSON)
          success "Arjun JSON -> $url"
          arjun -u "$url" -m JSON --include "{}" -t "$THREADS" --rate-limit "$RL" -oJ "$OUT/arjun-json/${stem}-JSON.json" "${ARJUN_HDRS[@]}" || true
          ((ARJUN_COUNT++)); ((MODE_COUNTS["$m"]++))
          ;;
        POST)
          success "Arjun POST -> $url"
          arjun -u "$url" -m POST -t "$THREADS" --rate-limit "$RL" -oJ "$OUT/arjun-json/${stem}-POST.json" "${ARJUN_HDRS[@]}" || true
          ((ARJUN_COUNT++)); ((MODE_COUNTS["$m"]++))
          ;;
        XML)
          success "Arjun XML -> $url"
          arjun -u "$url" -m XML  -t "$THREADS" --rate-limit "$RL" -oJ "$OUT/arjun-json/${stem}-XML.json"  "${ARJUN_HDRS[@]}" || true
          ((ARJUN_COUNT++)); ((MODE_COUNTS["$m"]++))
          ;;
        *) warn "Unknown Arjun mode: $mode" ;;
      esac
    done
  done < "$LIVE"
fi

VULNAPI_DISCOVER_TXT="$OUT/vulnapi-discover.txt"
VULNAPI_SCAN_DIR="$OUT/vulnapi-scans"
VULNAPI_OPENAPI_TXT="$OUT/vulnapi-openapi.txt"
mkdir -p "$VULNAPI_SCAN_DIR"

VULNAPI_COUNT=0; VULNAPI_OPENAPI_COUNT=0
if (( NO_VULNAPI == 0 )); then
  if command -v vulnapi >/dev/null 2>&1; then
    TARGET_DOMAIN="$(head -n1 "$HOSTS" | sed 's#^[a-zA-Z]*://##; s#/.*$##; s/:.*$//')"
    info "VulnAPI discover on https://$TARGET_DOMAIN ..."
    # Discover endpoints / well-known (VulnAPI docs: discover, scan curl, scan openapi) [1](https://vulnapi.cerberauth.com/docs)[2](https://github.com/cerberauth/vulnapi)
    vulnapi discover api "https://$TARGET_DOMAIN" > "$VULNAPI_DISCOVER_TXT" 2>/dev/null || true

    # Scan each live endpoint via curl-like CLI (headers supported) [1](https://vulnapi.cerberauth.com/docs)
    while IFS= read -r url; do
      [[ -z "$url" ]] && continue
      stem=$(printf "%s" "$url" | md5sum | cut -d" " -f1)
      # Build header flags for vulnapi (it accepts curl-like options -H) [1](https://vulnapi.cerberauth.com/docs)
      VA_HDRS=(); for h in "${HDRS[@]}"; do VA_HDRS+=(-H "$h"); done
      info "VulnAPI scan curl -> $url"
      vulnapi scan curl "$url" "${VA_HDRS[@]}" > "$VULNAPI_SCAN_DIR/${stem}.txt" 2>/dev/null || true
      ((VULNAPI_COUNT++))
    done < "$LIVE"

    # Optional OpenAPI scan if user provides or discover found any spec URL
    OPENAPI_SRC="$VULNAPI_OPENAPI"
    if [[ -z "$OPENAPI_SRC" ]]; then
      # Try to extract openapi URL from discover output (heuristic)
      OPENAPI_SRC="$(grep -Eo 'https?://[^ ]+/(openapi|swagger)\.json' "$VULNAPI_DISCOVER_TXT" | head -n1 || true)"
    fi
    if [[ -n "$OPENAPI_SRC" ]]; then
      info "VulnAPI scan openapi -> $OPENAPI_SRC"
      if [[ -n "$VULNAPI_TOKEN" ]]; then
        echo "$VULNAPI_TOKEN" | vulnapi scan openapi "$OPENAPI_SRC" > "$VULNAPI_OPENAPI_TXT" 2>/dev/null || true
      else
        # Attempt without token (if spec permits) [1](https://vulnapi.cerberauth.com/docs)
        vulnapi scan openapi "$OPENAPI_SRC" > "$VULNAPI_OPENAPI_TXT" 2>/dev/null || true
      fi
      ((VULNAPI_OPENAPI_COUNT++))
    fi
  else
    warn "VulnAPI not found; skipping (install: https://github.com/cerberauth/vulnapi)"
  fi
fi

MANTRA_TXT="$OUT/mantra-findings.txt"; : > "$MANTRA_TXT"
MANTRA_COUNT=0
if (( NO_MANTRA == 0 )); then
  if command -v mantra >/dev/null 2>&1; then
    info "Running Mantra on JS/HTML URLs (from recon) ..."
    # Accept URLs via stdin per tool README [3](https://github.com/brosck/mantra)
    cat "$ALL_JS" | mantra > "$MANTRA_TXT" 2>/dev/null || true
    MANTRA_COUNT=$(grep -c . "$MANTRA_TXT" 2>/dev/null || echo 0)
  else
    warn "Mantra not found; skipping (install: go install github.com/Brosck/mantra@latest)" # [3](https://github.com/brosck/mantra)
  fi
fi

DALFOX_OUT_JSON="$OUT/dalfox-results.json"; : > "$DALFOX_OUT_JSON"
DALFOX_COUNT=0
if (( NO_DALFOX == 0 )); then
  if command -v dalfox >/dev/null 2>&1; then
    info "Running Dalfox on live endpoints (XSS scan) ..."
    # Dalfox file mode supports headers, output and JSON format; blind XSS via -b URL [4](https://dalfox.hahwul.com/page/usage/)[5](https://dalfox.hahwul.com/advanced/features/command-flags/)
    DFLAGS=(file "$LIVE" --format json -o "$DALFOX_OUT_JSON" "${DALFOX_HDRS[@]}")
    [[ -n "$DALFOX_BLIND" ]] && DFLAGS+=(-b "$DALFOX_BLIND")
    dalfox "${DFLAGS[@]}" >/dev/null 2>&1 || true
    # Count findings by counting JSON objects (best-effort)
    DALFOX_COUNT=$(grep -c '"PoC"' "$DALFOX_OUT_JSON" 2>/dev/null || echo 0)
  else
    warn "Dalfox not found; skipping (usage: dalfox file urls.txt ...)" # [4](https://dalfox.hahwul.com/page/usage/)
  fi
fi


RAW_COUNT=$(wc -l < "$ENDPOINTS_RAW" 2>/dev/null || echo 0)
LIVE_COUNT=$(wc -l < "$LIVE" 2>/dev/null || echo 0)

echo
success "Summary Report"
echo "    Total raw endpoints:   $RAW_COUNT"
echo "    Total live endpoints:  $LIVE_COUNT"
echo "    Arjun scans executed:  $ARJUN_COUNT"
for m in ${METHODS//,/ } ; do echo "    - $m: ${MODE_COUNTS[$m]:-0}"; done
echo "    VulnAPI curl scans:    $VULNAPI_COUNT"
echo "    VulnAPI openapi scans: $VULNAPI_OPENAPI_COUNT"
echo "    Mantra findings:       $MANTRA_COUNT"
echo "    Dalfox XSS findings:   $DALFOX_COUNT"
echo "    Output directory:      $OUT"


if (( JSON_SUMMARY == 1 )); then
  SUMMARY_JSON="$OUT/summary.json"
  {
    echo "{"
    echo "  \"raw_endpoints\": $RAW_COUNT,"
    echo "  \"live_endpoints\": $LIVE_COUNT,"
    echo "  \"arjun_scans\": $ARJUN_COUNT,"
    echo "  \"mode_counts\": {"
    first=1
    for m in ${METHODS//,/ } ; do
      [[ $first -eq 0 ]] && echo ","
      printf "    \"%s\": %s" "$m" "${MODE_COUNTS[$m]:-0}"
      first=0
    done
    echo
    echo "  },"
    echo "  \"vulnapi_curl_scans\": $VULNAPI_COUNT,"
    echo "  \"vulnapi_openapi_scans\": $VULNAPI_OPENAPI_COUNT,"
    echo "  \"mantra_findings\": $MANTRA_COUNT,"
    echo "  \"dalfox_findings\": $DALFOX_COUNT,"
    echo "  \"output_directory\": \"$(printf '%s' "$OUT" | sed 's/\"/\\\"/g')\""
    echo "}"
  } > "$SUMMARY_JSON"
  success "JSON summary saved to $SUMMARY_JSON"
fi

export OUT ENDPOINTS_RAW LIVE DALFOX_OUT_JSON MANTRA_TXT VULNAPI_DISCOVER_TXT VULNAPI_SCAN_DIR VULNAPI_OPENAPI_TXT
python3 - "$OUT" "$ENDPOINTS_RAW" "$LIVE" "$DALFOX_OUT_JSON" "$MANTRA_TXT" "$VULNAPI_DISCOVER_TXT" "$VULNAPI_SCAN_DIR" "$VULNAPI_OPENAPI_TXT" <<'PY' || true
import sys, os, json, re, glob, html, collections

out_dir, raw_path, live_path, dalfox_json_path, mantra_path, vulnapi_discover_path, vulnapi_scan_dir, vulnapi_openapi_path = sys.argv[1:]

def read_lines(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return [l.rstrip('\n') for l in f]
    except Exception:
        return []

def try_json_load(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            txt = f.read().strip()
        # Dalfox may output a single JSON or JSON lines; handle both
        if not txt:
            return []
        if txt.startswith('{') or txt.startswith('['):
            data = json.loads(txt)
            if isinstance(data, dict): return [data]
            if isinstance(data, list): return data
        # JSONL
        items = []
        for line in txt.splitlines():
            line = line.strip()
            if line.startswith('{'):
                try:
                    items.append(json.loads(line))
                except Exception:
                    pass
        return items
    except Exception:
        return []

# Raw & Live
raw_urls = [u.strip() for u in read_lines(raw_path) if u.strip().startswith('http')]
live_lines = [l.strip() for l in read_lines(live_path) if l.strip()]
live = []
status_buckets = collections.Counter()
for line in live_lines:
    m = re.match(r'^(https?://\S+?)(?:\s+\[(\d{3})\])?$', line)
    if m:
        url = m.group(1); status = m.group(2) or ''
        live.append({'url': url, 'status': status})
        if status:
            s = int(status)
            if   200 <= s < 300: status_buckets['2xx'] += 1
            elif 300 <= s < 400: status_buckets['3xx'] += 1
            elif 400 <= s < 500: status_buckets['4xx'] += 1
            elif 500 <= s < 600: status_buckets['5xx'] += 1
    else:
        live.append({'url': line, 'status': ''})

# Dalfox findings
dalfox_findings = try_json_load(dalfox_json_path)
dalfox_count = 0
dalfox_rows = []
for item in dalfox_findings:
    # Dalfox commonly includes fields: PoC, type, target, payload; not guaranteed—best effort
    poc = item.get('PoC') or item.get('poc') or ''
    target = item.get('target') or item.get('Target') or item.get('url') or ''
    xtype = item.get('type') or item.get('xss_type') or 'XSS'
    payload = item.get('payload') or item.get('Payload') or ''
    dalfox_rows.append({'poc': poc, 'target': target, 'type': xtype, 'payload': payload})
    dalfox_count += 1

# Mantra findings (plain text)
mantra_lines = [l for l in read_lines(mantra_path) if l.strip()]
mantra_rows = []
key_regex = re.compile(r'(?i)(api[_-]?key|access[_-]?key|secret|token|keyid|client[_-]?id|auth)', re.I)
for i, line in enumerate(mantra_lines):
    url_match = re.findall(r'https?://\S+', line)
    kind = 'Leak' if key_regex.search(line) else ''
    mantra_rows.append({'line': line, 'urls': url_match, 'kind': kind})
mantra_count = len([r for r in mantra_rows if r['kind'] == 'Leak'])

# VulnAPI discover & scans (text)
vulnapi_discover = read_lines(vulnapi_discover_path)
vulnapi_scan_files = sorted(glob.glob(os.path.join(vulnapi_scan_dir, '*.txt')))
vulnapi_openapi_txt = read_lines(vulnapi_openapi_path) if os.path.isfile(vulnapi_openapi_path) else []
vulnapi_rows = []
sev_counter = collections.Counter()
for path in vulnapi_scan_files:
    lines = read_lines(path)
    # Heuristic severity parsing (look for "High", "Medium", "Low")
    sev = ''
    for l in lines:
        if re.search(r'\bHigh\b', l): sev = 'High'; break
        if re.search(r'\bMedium\b', l): sev = 'Medium'
        if re.search(r'\bLow\b', l) and not sev: sev = 'Low'
    if sev: sev_counter[sev] += 1
    title = ''
    for l in lines:
        m = re.search(r'Vulnerability:\s*(.+)', l)
        if m: title = m.group(1); break
    vulnapi_rows.append({'file': os.path.basename(path), 'severity': sev, 'title': title, 'preview': (lines[:6] if lines else [])})

# Arjun findings aggregation (top params)
arjun_dir = os.path.join(out_dir, 'arjun-json')
params_freq = collections.Counter()
arjun_rows = []
for path in glob.glob(os.path.join(arjun_dir, '*.json')):
    base = os.path.basename(path)
    mm = re.search(r'-(GET|POST|JSON|XML)\.json$', base)
    mode = mm.group(1) if mm else 'UNKNOWN'
    url = ''
    params = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        if isinstance(data, dict):
            url = data.get('URL') or data.get('url') or data.get('Endpoint') or data.get('endpoint') or ''
            par = data.get('Parameters') or data.get('parameters') or data.get('params') or []
            if isinstance(par, dict): params = list(par.keys())
            elif isinstance(par, list): params = par
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    if not url: url = item.get('URL') or item.get('url') or ''
                    par = item.get('Parameters') or item.get('parameters') or item.get('params') or []
                    if isinstance(par, dict): params.extend(list(par.keys()))
                    elif isinstance(par, list): params.extend(par)
    except Exception:
        pass
    for p in params: params_freq[p] += 1
    arjun_rows.append({'file': base, 'mode': mode, 'url': url, 'params': params, 'params_count': len(params)})

top_params = params_freq.most_common(15)

# Sensitive keyword highlights in endpoints
sensitive_keywords = ['admin','login','debug','token','auth','key','secret','password','oauth','jwt']
sensitive_hits = []
for e in raw_urls[:1000]:
    hit = [k for k in sensitive_keywords if k.lower() in e.lower()]
    if hit:
        sensitive_hits.append({'url': e, 'keys': hit})

summary = {
    'raw_count': len(raw_urls),
    'live_count': len(live),
    'dalfox_count': dalfox_count,
    'mantra_count': mantra_count,
    'vulnapi_count': sum(sev_counter.values()),
    'vulnapi_sev': {k:v for k,v in sev_counter.items()},
    'status_buckets': status_buckets
}

def esc(s): return html.escape(str(s), quote=True)

# HTML
html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>API Security Audit Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{ --bg:#0f172a; --card:#111827; --text:#e5e7eb; --muted:#9ca3af; --accent:#22d3ee; --ok:#10b981; --warn:#f59e0b; --err:#ef4444; }}
  body {{ background:var(--bg); color:var(--text); font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif; margin:0; }}
  header {{ padding:18px 24px; border-bottom:1px solid #1f2937; display:flex; align-items:center; justify-content:space-between; }}
  h1 {{ font-size:20px; margin:0; }}
  .container {{ padding:24px; }}
  .cards {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:16px; margin-bottom:24px; }}
  .card {{ background:var(--card); border:1px solid #1f2937; border-radius:10px; padding:16px; }}
  .card h2 {{ font-size:13px; margin:0 0 8px; color:var(--muted); font-weight:600; letter-spacing:.4px; text-transform:uppercase; }}
  .metric {{ font-size:32px; font-weight:700; }}
  .chart {{ background:var(--card); border:1px solid #1f2937; border-radius:10px; padding:16px; margin-bottom:24px; }}
  .section {{ margin-bottom:24px; }}
  .section h3 {{ margin:0 0 12px; font-size:16px; }}
  table {{ width:100%; border-collapse: collapse; background:var(--card); border:1px solid #1f2937; border-radius:10px; overflow:hidden; }}
  th, td {{ padding:10px 12px; border-bottom:1px solid #1f2937; font-size:13px; }}
  th {{ text-align:left; color:var(--muted); font-weight:600; letter-spacing:.3px; text-transform:uppercase; }}
  tr:hover td {{ background:#0b1220; }}
  .pill {{ display:inline-block; padding:4px 8px; border-radius:999px; background:#0b1220; border:1px solid #1f2937; margin:2px; font-size:12px; }}
  .status {{ font-weight:600; }}
  .status.ok {{ color:var(--ok); }}
  .status.warn {{ color:var(--warn); }}
  .status.err {{ color:var(--err); }}
  .muted {{ color:var(--muted); }}
  .btn {{ padding:6px 10px; background:#0b1220; color:var(--text); border:1px solid #1f2937; border-radius:8px; cursor:pointer; font-size:13px; margin-right:8px; }}
  footer {{ padding:16px 24px; border-top:1px solid #1f2937; color:var(--muted); font-size:12px; }}
</style>
</head>
<body>
<header>
  <h1>API Security Audit Dashboard</h1>
  <div class="muted">Generated: {esc(__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</div>
</header>
<div class="container">

  <div class="cards">
    <div class="card"><h2>Raw Endpoints</h2><div class="metric">{summary['raw_count']}</div></div>
    <div class="card"><h2>Live Endpoints</h2><div class="metric">{summary['live_count']}</div></div>
    <div class="card"><h2>Arjun Scans</h2><div class="metric">{len(arjun_rows)}</div></div>
    <div class="card"><h2>VulnAPI Findings</h2><div class="metric">{summary['vulnapi_count']}</div></div>
    <div class="card"><h2>Dalfox (XSS)</h2><div class="metric">{summary['dalfox_count']}</div></div>
    <div class="card"><h2>Mantra Leaks</h2><div class="metric">{summary['mantra_count']}</div></div>
  </div>

  <div class="chart">
    <h3>Counts Overview</h3>
    <canvas id="barCounts" style="width:100%;height:160px"></canvas>
  </div>

  <div class="chart">
    <h3>Status Code Distribution</h3>
    <canvas id="statusDist" style="width:100%;height:160px"></canvas>
    <div class="muted">Buckets: {', '.join(f"{k}: {v}" for k,v in summary['status_buckets'].items()) or 'No data'}</div>
  </div>

  <div class="chart">
    <h3>VulnAPI Severity</h3>
    <canvas id="vulnSev" style="width:100%;height:160px"></canvas>
  </div>

  <div class="section">
    <button class="btn" onclick="toggle('raw-section')">Toggle Raw</button>
    <button class="btn" onclick="toggle('live-section')">Toggle Live</button>
    <button class="btn" onclick="toggle('arjun-section')">Toggle Arjun</button>
    <button class="btn" onclick="toggle('vulnapi-section')">Toggle VulnAPI</button>
    <button class="btn" onclick="toggle('dalfox-section')">Toggle Dalfox</button>
    <button class="btn" onclick="toggle('mantra-section')">Toggle Mantra</button>
    <button class="btn" onclick="toggle('sensitive-section')">Toggle Sensitive URLs</button>
  </div>

  <div class="section" id="raw-section">
    <h3>Raw Endpoints (up to 200)</h3>
    <table><thead><tr><th>#</th><th>URL</th></tr></thead><tbody>
      {''.join(f"<tr><td>{i+1}</td><td>{esc(u)}</td></tr>" for i,u in enumerate(raw_urls[:200])) or "<tr><td colspan='2' class='muted'>No data</td></tr>"}
    </tbody></table>
  </div>

  <div class="section" id="live-section" style="display:none;">
    <h3>Live Endpoints (up to 200)</h3>
    <table><thead><tr><th>#</th><th>URL</th><th>Status</th></tr></thead><tbody>
      {''.join(f"<tr><td>{i+1}</td><td>{esc(x['url'])}</td><td class='status {('ok' if (x['status'] and x['status'].isdigit() and int(x['status'])<400) else ('warn' if x['status'] in ('401','403','405') else ('err' if x['status'] else '')))}'>{esc(x['status']) or '-'}</td></tr>" for i,x in enumerate(live[:200])) or "<tr><td colspan='3' class='muted'>No data</td></tr>"}
    </tbody></table>
  </div>

  <div class="section" id="arjun-section" style="display:none;">
    <h3>Arjun Findings (up to 200)</h3>
    <table><thead><tr><th>#</th><th>Mode</th><th>URL</th><th>Parameters (count)</th><th>Sample</th></tr></thead><tbody>
      {''.join(f"<tr><td>{i+1}</td><td>{esc(f['mode'])}</td><td>{esc(f['url']) or '-'}</td><td>{f['params_count']}</td><td>{' '.join('<span class=\\'pill\\'>'+esc(p)+'</span>' for p in f['params'][:10]) or '-'}</td></tr>" for i,f in enumerate(arjun_rows[:200])) or "<tr><td colspan='5' class='muted'>No data</td></tr>"}
    </tbody></table>

    <h3>Top Parameters</h3>
    <div>{' '.join(f"<span class='pill'>{esc(p)}</span>" for p,_ in top_params) or '<span class=\"muted\">No parameters</span>'}</div>
  </div>

  <div class="section" id="vulnapi-section" style="display:none;">
    <h3>VulnAPI Findings (heuristic summary)</h3>
    <table><thead><tr><th>#</th><th>File</th><th>Severity</th><th>Title</th><th>Preview</th></tr></thead><tbody>
      {''.join(f"<tr><td>{i+1}</td><td>{esc(r['file'])}</td><td>{esc(r['severity']) or '-'}</td><td>{esc(r['title']) or '-'}</td><td><pre style='white-space:pre-wrap'>{esc('\\n'.join(r['preview']))}</pre></td></tr>" for i,r in enumerate(vulnapi_rows[:100])) or "<tr><td colspan='5' class='muted'>No data</td></tr>"}
    </tbody></table>

    <h3>Discover Output (first 100 lines)</h3>
    <pre style="white-space:pre-wrap; background:#0b1220; padding:12px; border:1px solid #1f2937; border-radius:8px;">{esc('\\n'.join(vulnapi_discover[:100])) or 'No discover output'}</pre>

    <h3>OpenAPI Scan Output (first 100 lines)</h3>
    <pre style="white-space:pre-wrap; background:#0b1220; padding:12px; border:1px solid #1f2937; border-radius:8px;">{esc('\\n'.join(vulnapi_openapi_txt[:100])) or 'No openapi output'}</pre>
  </div>

  <div class="section" id="dalfox-section" style="display:none;">
    <h3>Dalfox XSS Findings (up to 200)</h3>
    <table><thead><tr><th>#</th><th>Type</th><th>Target</th><th>Payload</th><th>PoC</th></tr></thead><tbody>
      {''.join(f"<tr><td>{i+1}</td><td>{esc(r['type'])}</td><td>{esc(r['target'])}</td><td><code>{esc(r['payload'])}</code></td><td><code>{esc(r['poc'])}</code></td></tr>" for i,r in enumerate(dalfox_rows[:200])) or "<tr><td colspan='5' class='muted'>No data</td></tr>"}
    </tbody></table>
  </div>

  <div class="section" id="mantra-section" style="display:none;">
    <h3>Mantra Key/Secret Findings (up to 200)</h3>
    <table><thead><tr><th>#</th><th>Line</th><th>URLs</th></tr></thead><tbody>
      {''.join(f"<tr><td>{i+1}</td><td><pre style='white-space:pre-wrap'>{esc(r['line'])}</pre></td><td>{esc(', '.join(r['urls'])) or '-'}</td></tr>" for i,r in enumerate([x for x in mantra_rows if x['kind']=='Leak'][:200])) or "<tr><td colspan='3' class='muted'>No data</td></tr>"}
    </tbody></table>
  </div>

  <div class="section" id="sensitive-section" style="display:none;">
    <h3>Endpoints with Sensitive Keywords</h3>
    <table><thead><tr><th>#</th><th>URL</th><th>Keywords</th></tr></thead><tbody>
      {''.join(f"<tr><td>{i+1}</td><td>{esc(hit['url'])}</td><td>{esc(', '.join(hit['keys']))}</td></tr>" for i,hit in enumerate(sensitive_hits[:200])) or "<tr><td colspan='3' class='muted'>No data</td></tr>"}
    </tbody></table>
  </div>

</div>
<footer>
  <span class="muted">Artifacts located in: {esc(out_dir)}</span>
</footer>

<script>
// Tiny chart renderer (no libs)
function bar(canvasId, labels, values, colors) {
  const canvas = document.getElementById(canvasId);
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.clientWidth;
  const h = canvas.height = canvas.clientHeight;
  const pad = 32; const max = Math.max(1, ...values); const bw = (w - pad*2)/(values.length*1.5);
  ctx.fillStyle = '#1f2937'; ctx.fillRect(0,0,w,h); ctx.font='12px system-ui';
  values.forEach((v,i)=>{
    const x = pad + i*bw*1.5, bh = Math.round((v/max)*(h-60));
    ctx.fillStyle = colors[i]; ctx.fillRect(x, h-30-bh, bw, bh);
    ctx.fillStyle = '#e5e7eb'; ctx.fillText(labels[i], x, h-12); ctx.fillText(String(v), x, h-40-bh);
  });
}
function toggle(id){ const el=document.getElementById(id); el.style.display=(el.style.display==='none'?'block':'none'); }

// Render charts
bar('barCounts', ['Raw','Live','Arjun','VulnAPI','Dalfox','Mantra'],
  [{raw_count},{live_count},{arjun_len},{vulnapi_count},{dalfox_count},{mantra_count}],
  ['#22d3ee','#10b981','#f59e0b','#ef4444','#8b5cf6','#e11d48']
);
bar('statusDist', ['2xx','3xx','4xx','5xx'],
  [{s2},{s3},{s4},{s5}],
  ['#10b981','#22d3ee','#f59e0b','#ef4444']
);
bar('vulnSev', ['High','Medium','Low'],
  [{sevH},{sevM},{sevL}],
  ['#ef4444','#f59e0b','#10b981']
);
</script>
</body>
</html>
""".replace('{raw_count}', str(summary['raw_count'])) \
   .replace('{live_count}', str(summary['live_count'])) \
   .replace('{arjun_len}', str(len(arjun_rows))) \
   .replace('{vulnapi_count}', str(summary['vulnapi_count'])) \
   .replace('{dalfox_count}', str(summary['dalfox_count'])) \
   .replace('{mantra_count}', str(summary['mantra_count'])) \
   .replace('{s2}', str(summary['status_buckets'].get('2xx',0))) \
   .replace('{s3}', str(summary['status_buckets'].get('3xx',0))) \
   .replace('{s4}', str(summary['status_buckets'].get('4xx',0))) \
   .replace('{s5}', str(summary['status_buckets'].get('5xx',0))) \
   .replace('{sevH}', str(summary['vulnapi_sev'].get('High',0))) \
   .replace('{sevM}', str(summary['vulnapi_sev'].get('Medium',0))) \
   .replace('{sevL}', str(summary['vulnapi_sev'].get('Low',0)))

os.makedirs(out_dir, exist_ok=True)
with open(os.path.join(out_dir, 'dashboard.html'), 'w', encoding='utf-8') as f:
    f.write(html_doc)
print(f"[+] HTML dashboard saved to {os.path.join(out_dir, 'dashboard.html')}")
PY

echo
success "Complete. Artifacts in: $OUT/"
echo "    - endpoints-raw.txt     (absolute URLs only)"
echo "    - endpoints-live.txt    (filtered by httpx)"
echo "    - arjun-json/*.json     (per-endpoint parameter findings)"
echo "    - vulnapi-discover.txt  (discover output)"
echo "    - vulnapi-scans/*.txt   (curl-mode scan outputs)"
echo "    - vulnapi-openapi.txt   (openapi scan output, if any)"
echo "    - mantra-findings.txt   (JS/HTML key/secret leaks)"
echo "    - dalfox-results.json   (XSS findings)"
echo "    - dashboard.html        (interactive security report)"
