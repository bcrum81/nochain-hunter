#!/usr/bin/env bash
#
# nochain-scan.sh - find (and optionally quarantine) files from the
# EtherHiding / "nochain" WordPress compromise.
#
# Needs nothing but bash, find and grep. Does not require WordPress to be
# running, installed, or unsuspended. Scans every site under one account
# in a single pass.
#
#   ./nochain-scan.sh                     scan ~/www, report only
#   ./nochain-scan.sh --root /path        scan somewhere else
#   ./nochain-scan.sh --quarantine        move findings out of the web root
#   ./nochain-scan.sh --delete            permanently remove HIGH findings
#   ./nochain-scan.sh --delete --no-archive   ... without keeping a copy
#   ./nochain-scan.sh --sw                neutralise service workers
#   ./nochain-scan.sh --restore BATCH     put a quarantine batch back
#   ./nochain-scan.sh --list              list quarantine batches
#
# --quarantine moves files to ~/nochain-quarantine/ with a manifest, and
# --restore puts them back. --delete is irreversible: it writes a single
# tar.gz of everything it removed to ~/nochain-removed-<batch>.tar.gz (unless
# --no-archive) and then unlinks the originals.

set -uo pipefail
export LC_ALL=C

ROOT="${HOME}/www"
QROOT="${HOME}/nochain-quarantine"
# Our own mu-plugin (wp-hardening/). It contains the signatures it blocks, so
# it must be exempt from them.
GUARD='000-nochain-guard.php'
MODE="scan"
BATCH_ARG=""
ARCHIVE=1
REPORT="${HOME}/nochain-report-$(date -u +%Y%m%d-%H%M%S).txt"

RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; DIM=$'\033[2m'; OFF=$'\033[0m'
if [ ! -t 1 ]; then RED=""; YEL=""; GRN=""; DIM=""; OFF=""; fi

while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT="$2"; shift 2 ;;
    --quarantine) MODE="quarantine"; shift ;;
    --delete|--purge) MODE="delete"; shift ;;
    --no-archive) ARCHIVE=0; shift ;;
    --sw) MODE="sw"; shift ;;
    --restore) MODE="restore"; BATCH_ARG="${2:-}"; shift 2 ;;
    --list) MODE="list"; shift ;;
    -h|--help) sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

HITS_FILE="$(mktemp)"
trap 'rm -f "$HITS_FILE"' EXIT

# record <severity> <path> <reason>
record() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$HITS_FILE"
}

banner() {
  echo "${DIM}  checking $1${OFF}"
}

# Only treat a 10-digit suffix as an attacker timestamp if it decodes to a
# plausible date. Stops legitimate names like "wp-rocket-1234567890" (2009)
# from being flagged.
TS_MIN=1672531200                       # 2023-01-01
TS_MAX=$(( $(date -u +%s) + 31536000 )) # one year ahead
plausible_ts() {
  [ "$1" -ge "$TS_MIN" ] 2>/dev/null && [ "$1" -le "$TS_MAX" ] 2>/dev/null
}

# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

scan_all() {
  [ -d "$ROOT" ] || { echo "Root not found: $ROOT" >&2; exit 1; }
  echo "Scanning ${ROOT}"
  echo "Report:   ${REPORT}"

  local PRUNE=( -path '*/node_modules' -o -path '*/.git' -o -path "$QROOT" \
                -o -path '*/wp-content/cache' -o -path '*/wp-content/upgrade' )

  banner "timestamp-named plugin and theme directories"
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    local ts human
    ts="$(basename "$d" | grep -oE '1[0-9]{9}$')"
    plausible_ts "$ts" || continue
    human="$(date -u -d "@${ts}" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || echo "epoch ${ts}")"
    record HIGH "$d" "directory named with a unix timestamp (${human}) - attacker naming convention"
  done < <(find "$ROOT" \( "${PRUNE[@]}" \) -prune -o -type d -print 2>/dev/null \
             | grep -E '/(plugins|themes)/[^/]*[-_]1[0-9]{9}$')

  banner "nochain directories and root service workers"
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    record HIGH "$d" "directory named 'nochain' - service worker payload"
  done < <(find "$ROOT" -type d -name nochain 2>/dev/null)

  while IFS= read -r f; do
    [ -n "$f" ] || continue
    record HIGH "$f" "service worker file at a site root"
  done < <(find "$ROOT" -maxdepth 3 -type f \( -name 'nochain-sw.js' -o -name 'nc-sw.js' \) 2>/dev/null)

  banner "PHP under uploads"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    record HIGH "$f" "PHP file inside uploads - never legitimate"
  done < <(find "$ROOT" -path '*/uploads/*' -type f -name '*.php' 2>/dev/null)

  banner "archives and scripts disguised as images"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local magic
    magic="$(head -c 4 "$f" 2>/dev/null | tr -d '\0')"
    case "$magic" in
      PK*)   record HIGH "$f" "ZIP archive wearing an image extension - self-repair payload" ;;
      '<?ph'|'<?='*) record HIGH "$f" "PHP code wearing an image extension" ;;
    esac
  done < <(find "$ROOT" -path '*/uploads/*' -type f -size +20k \
             \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.webp' -o -iname '*.ico' \) 2>/dev/null)

  banner "must-use plugins"
  local ALLOW='^(index\.php|000-nochain-guard\.php|001-block-user-enumeration\.php|\.htaccess|readme\.txt|kinsta-mu-plugins(\.php)?|sso(-cli)?\.php|sg-cachepress|siteground-optimizer-mu-plugin\.php|wp-stack-cache\.php|endurance-.*\.php|wpe-wp-sign-on-plugin\.php|wpengine-security-auditor\.php|gd-system-plugin\.php|0-liquidweb\.php|pressable-scripts\.php|cloudways\.php|breeze-mu-plugin\.php|mu-plugin\.php)$'
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    local base sev
    base="$(basename "$p")"
    if printf '%s' "$base" | grep -qE "$ALLOW"; then continue; fi
    sev=MEDIUM
    case "$base" in nc-dropin*|nc_dropin*) sev=HIGH ;; esac
    record "$sev" "$p" "unrecognised must-use plugin - loads on every request, invisible in the Plugins list"
  done < <(find "$ROOT" -path '*/mu-plugins/*' -mindepth 1 -maxdepth 1 2>/dev/null)

  banner "timestamp-named PHP files"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local ts human
    ts="$(basename "$f" | grep -oE '1[0-9]{9}' | tail -1)"
    plausible_ts "$ts" || continue
    human="$(date -u -d "@${ts}" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || echo "epoch ${ts}")"
    record HIGH "$f" "filename carries a unix timestamp (${human})"
  done < <(find "$ROOT" -path '*/wp-content/*' -type f -print 2>/dev/null \
             | grep -E '[-_.]1[0-9]{9}\.php$')

  banner "self-repair state files"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    record MEDIUM "$f" "integrity signature file used by the self-repair routine"
  done < <(find "$ROOT" -path '*/plugins/*' -type f -name '.state.json' 2>/dev/null)

  banner "attacker-named plugin and drop directories"
  # "Query Monitor Companion" ships as site-helper-<hex>; the display name is
  # chosen per site, so match the directory shape instead. The tail must hold
  # both a digit and an a-f letter: the digit rules out dictionary-word endings
  # (wp-facade, my-decade), the letter rules out version and epoch suffixes
  # (wp-rocket-1234567890), which the timestamp rule above already handles.
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    record HIGH "$d" "plugin directory named <word>-<hex> - matches the 'Query Monitor Companion' dropper"
  done < <(find "$ROOT" -type d -print 2>/dev/null \
             | grep -E '/(plugins|themes)/[a-z]+(-[a-z]+)*-[0-9a-f]{6,}$' \
             | grep -E -- '-[0-9a-f]*[0-9][0-9a-f]*$' \
             | grep -E -- '-[0-9a-f]*[a-f][0-9a-f]*$')

  while IFS= read -r d; do
    [ -n "$d" ] || continue
    record HIGH "$d" "known drop directory used by this operator"
  done < <(find "$ROOT" -path '*/wp-content/*' -type d \
             \( -name 'webtoffee_export' -o -name 'nc-dropin' \) 2>/dev/null)

  banner "code signatures"
  sig_grep 'HIGH'   'nochain|nc[-_]dropin|nc_skip=1|__ncSkip|__ncR\b|wpFrontProbe|nochain-demo-frame' \
           'nochain loader or evasion marker'
  sig_grep 'HIGH'   '0x58460d0b3d4d6b03761c89120393c0c676676496' \
           'known payload contract address'
  sig_grep 'HIGH'   'mainnet\.base\.org|base\.publicnode\.com|base\.drpc\.org|1rpc\.io/base|blastapi\.io|gateway\.tenderly\.co' \
           'blockchain RPC endpoint referenced from site code'
  sig_grep 'HIGH'   'getActiveScripts' 'smart-contract ABI used to fetch a remote payload' 'hasDemoPage'
  sig_grep 'HIGH'   'extractTo' 'self-repair: unpacks an archive into the plugins directory' 'ZipArchive'
  sig_grep 'HIGH'   'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13|gzuncompress)' \
           'PHP backdoor: eval of an encoded payload'
  sig_grep 'MEDIUM' 'JsonRpcProvider' 'bundled Ethereum client library inside the site'

  banner "administrator concealment"
  # A separate family from nochain: hides a rogue admin account rather than
  # serving a payload. Seen in the wild.
  sig_grep 'HIGH'   '_pre_user_id' \
           'option used by WordPress admin-hiding malware to store concealed account IDs'
  sig_grep 'HIGH'   'wsh_tracked_admin_ids|WSH_HIDDEN_USERS|wsh_hidden_user_(ids|logins)' \
           'WP Security Helper dropper: hidden-administrator option and constant names'
  sig_grep 'HIGH'   'add_filter\([[:space:]]*.all_plugins' \
           'plugin hides itself from the Plugins list while filtering the Users list' 'pre_user_query'
  sig_grep 'HIGH'   'Author:[[:space:]]*WordPress Security Team' \
           'forged plugin authorship - impersonates wordpress.org'

  banner "generic contract addresses"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in */mu-plugins/"$GUARD") continue ;; esac
    if grep -qiE '0x[a-f0-9]{40}' "$f" 2>/dev/null; then
      record HIGH "$f" "40-hex contract address alongside a blockchain endpoint - EtherHiding with a different contract"
    fi
  done < <(grep -rlIE --include='*.php' --include='*.js' \
             'base\.org|publicnode|drpc\.org|blastapi|tenderly' "$ROOT" 2>/dev/null)
}

# sig_grep SEVERITY PATTERN REASON [ALSO_REQUIRED]
sig_grep() {
  local sev="$1" pat="$2" reason="$3" also="${4:-}"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in "$QROOT"/*|*/mu-plugins/"$GUARD") continue ;; esac
    if [ -n "$also" ] && ! grep -qiE "$also" "$f" 2>/dev/null; then continue; fi
    record "$sev" "$f" "$reason"
  done < <(grep -rlIE --include='*.php' --include='*.js' --include='*.json' \
             --include='*.html' --include='*.htm' --include='*.inc' \
             "$pat" "$ROOT" 2>/dev/null)
}

# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

summarise() {
  local high med
  # Collapse duplicates, merging reasons per path.
  sort -u "$HITS_FILE" | awk -F'\t' '
    { key=$1"\t"$2; if (key in seen) seen[key]=seen[key]"; "$3; else { seen[key]=$3; order[++n]=key } }
    END { for (i=1;i<=n;i++) { split(order[i],p,"\t"); print p[1]"\t"p[2]"\t"seen[order[i]] } }
  ' > "${HITS_FILE}.merged"

  # Drop files that live inside an already-flagged directory.
  awk -F'\t' '$1=="HIGH"' "${HITS_FILE}.merged" | cut -f2 | while IFS= read -r d; do
    [ -d "$d" ] && printf '%s/\n' "$d"
  done > "${HITS_FILE}.dirs"

  : > "${HITS_FILE}.final"
  while IFS=$'\t' read -r sev path reason; do
    local skip=0
    while IFS= read -r d; do
      [ -n "$d" ] || continue
      case "$path/" in "$d"*) [ "$path/" != "$d" ] && skip=1 ;; esac
    done < "${HITS_FILE}.dirs"
    [ "$skip" -eq 0 ] && printf '%s\t%s\t%s\n' "$sev" "$path" "$reason" >> "${HITS_FILE}.final"
  done < "${HITS_FILE}.merged"

  {
    echo "nochain scan - $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "root: $ROOT"
    echo
    sort -t$'\t' -k1,1 "${HITS_FILE}.final" | while IFS=$'\t' read -r sev path reason; do
      printf '[%s] %s\n        %s\n' "$sev" "$path" "$reason"
    done
  } > "$REPORT" 2>/dev/null || {
    REPORT="${TMPDIR:-/tmp}/nochain-report-$$.txt"
    echo "(report path not writable; wrote $REPORT instead)" >&2
  }

  echo
  sort -t$'\t' -k1,1 "${HITS_FILE}.final" | while IFS=$'\t' read -r sev path reason; do
    local c="$YEL"; [ "$sev" = "HIGH" ] && c="$RED"
    printf '%s[%s]%s %s\n        %s%s%s\n' "$c" "$sev" "$OFF" "$path" "$DIM" "$reason" "$OFF"
  done

  high=$(awk -F'\t' '$1=="HIGH"' "${HITS_FILE}.final" | wc -l | tr -d ' ')
  med=$(awk -F'\t' '$1=="MEDIUM"' "${HITS_FILE}.final" | wc -l | tr -d ' ')
  echo
  if [ "$high" = "0" ] && [ "$med" = "0" ]; then
    echo "${GRN}Nothing found.${OFF}"
  else
    echo "${RED}${high} high${OFF}, ${YEL}${med} medium${OFF}. Full report: ${REPORT}"
  fi
}

# --------------------------------------------------------------------------
# Quarantine
# --------------------------------------------------------------------------

do_quarantine() {
  local batch dest manifest moved=0 failed=0
  batch="$(date -u +%Y%m%d-%H%M%S)"
  dest="${QROOT}/${batch}"
  manifest="${dest}/manifest.tsv"
  mkdir -p "$dest" || { echo "Cannot create $dest" >&2; exit 1; }
  : > "$manifest"

  # Must-use plugins first: they load earliest and rebuild the rest.
  awk -F'\t' '$1=="HIGH"' "${HITS_FILE}.final" | cut -f2 | \
    awk '{ print (index($0,"mu-plugins")?0:1) "\t" $0 }' | sort -k1,1n | cut -f2- | \
  while IFS= read -r p; do
    [ -e "$p" ] || continue
    case "$p" in "$QROOT"/*) continue ;; esac
    local rel target
    rel="${p#"$ROOT"/}"
    target="${dest}/${rel}"
    mkdir -p "$(dirname "$target")"
    if mv "$p" "$target" 2>/dev/null; then
      printf '%s\t%s\n' "$p" "$target" >> "$manifest"
      echo "${GRN}moved${OFF}  $rel"
      moved=$((moved+1))
    else
      echo "${RED}FAILED${OFF} $rel  (permissions, or deletion is blocked on this account)"
      failed=$((failed+1))
    fi
  done

  echo
  echo "Batch ${batch} written to ${dest}"
  echo "Manifest: ${manifest}"
  echo
  echo "${YEL}Re-run the scan now.${OFF} Anything that reappears means a live backdoor remains."
}

# --------------------------------------------------------------------------
# Deletion
# --------------------------------------------------------------------------

# Refuse to remove anything that isn't clearly an attacker artefact sitting
# inside the scanned tree. Deletion is irreversible and this script builds
# its own target list, so the list is what gets audited, not the rm call.
safe_to_remove() {
  local p="$1" rel base

  # Must be strictly inside ROOT, and not ROOT itself.
  case "$p" in
    "$ROOT"/?*) ;;
    *) echo "  ${RED}refused${OFF} (outside scan root): $p" >&2; return 1 ;;
  esac
  case "$p" in
    *../*|*/..) echo "  ${RED}refused${OFF} (path traversal): $p" >&2; return 1 ;;
  esac

  # Never remove WordPress's own structural directories, however they got
  # flagged. A signature hit inside one of these means the file is the
  # problem, not the directory.
  base="$(basename "$p")"
  case "$base" in
    public_html|wp-content|wp-includes|wp-admin|plugins|themes|uploads|mu-plugins|www|.|..)
      echo "  ${RED}refused${OFF} (structural directory): $p" >&2; return 1 ;;
  esac

  # Never remove a directory that is itself a WordPress install root.
  if [ -d "$p" ] && { [ -f "$p/wp-config.php" ] || [ -d "$p/wp-includes" ]; }; then
    echo "  ${RED}refused${OFF} (looks like a WordPress root): $p" >&2; return 1
  fi

  # Never remove a site's top-level directory (~/www/<domain>).
  rel="${p#"$ROOT"/}"
  case "$rel" in
    */*) ;;
    *) [ -d "$p" ] && { echo "  ${RED}refused${OFF} (site top level): $p" >&2; return 1; } ;;
  esac

  return 0
}

do_delete() {
  local batch targets n=0 removed=0 failed=0 archive=""
  batch="$(date -u +%Y%m%d-%H%M%S)"
  targets="$(mktemp)"

  # Must-use plugins first: they load earliest and rebuild the rest.
  awk -F'\t' '$1=="HIGH"' "${HITS_FILE}.final" | cut -f2 | \
    awk '{ print (index($0,"mu-plugins")?0:1) "\t" $0 }' | sort -k1,1n | cut -f2- | \
  while IFS= read -r p; do
    [ -e "$p" ] || continue
    case "$p" in "$QROOT"/*) continue ;; esac
    safe_to_remove "$p" || continue
    printf '%s\n' "$p"
  done > "$targets"

  n=$(wc -l < "$targets" | tr -d ' ')
  if [ "$n" -eq 0 ]; then
    echo "Nothing to delete."
    rm -f "$targets"
    return 0
  fi

  echo
  echo "${RED}About to permanently delete ${n} item(s):${OFF}"
  while IFS= read -r p; do
    [ -d "$p" ] && printf '  dir   %s\n' "$p" || printf '  file  %s\n' "$p"
  done < "$targets"

  echo
  read -r -p "Type DELETE to confirm: " ans
  if [ "$ans" != "DELETE" ]; then
    echo "Nothing deleted."
    rm -f "$targets"
    return 0
  fi

  if [ "$ARCHIVE" -eq 1 ]; then
    archive="${HOME}/nochain-removed-${batch}.tar.gz"
    if sed "s|^${ROOT}/||" "$targets" | \
         tar -czf "$archive" -C "$ROOT" -T - 2>/dev/null; then
      echo "${GRN}archived${OFF} $(basename "$archive") ($(wc -c < "$archive" | tr -d ' ') bytes)"
    else
      echo "${RED}Archive failed - refusing to delete without a copy.${OFF}" >&2
      echo "Re-run with --no-archive if you genuinely want no copy kept." >&2
      rm -f "$targets" "$archive"
      return 1
    fi
  fi

  echo
  while IFS= read -r p; do
    [ -e "$p" ] || continue
    if rm -rf -- "$p" 2>/dev/null && [ ! -e "$p" ]; then
      echo "${GRN}deleted${OFF} ${p#"$ROOT"/}"
      removed=$((removed+1))
    else
      echo "${RED}FAILED${OFF}  ${p#"$ROOT"/}  (permissions, or immutable)"
      failed=$((failed+1))
    fi
  done < "$targets"
  rm -f "$targets"

  echo
  echo "Deleted ${removed}, failed ${failed}."
  [ -n "$archive" ] && echo "Copy kept at ${archive} - remove it when you're satisfied."
  echo
  echo "${YEL}Re-run the scan now.${OFF} Anything that reappears means a live backdoor remains."
}

do_restore() {
  local dir="${QROOT}/${BATCH_ARG}" manifest
  manifest="${dir}/manifest.tsv"
  [ -f "$manifest" ] || { echo "No manifest at $manifest" >&2; exit 1; }
  while IFS=$'\t' read -r origin stored; do
    [ -e "$stored" ] || continue
    mkdir -p "$(dirname "$origin")"
    if mv "$stored" "$origin" 2>/dev/null; then
      echo "restored  $origin"
    else
      echo "FAILED    $origin"
    fi
  done < "$manifest"
}

do_list() {
  [ -d "$QROOT" ] || { echo "No quarantine directory yet."; exit 0; }
  for d in "$QROOT"/*/; do
    [ -d "$d" ] || continue
    local n
    n=$(wc -l < "${d}manifest.tsv" 2>/dev/null | tr -d ' ')
    printf '%s  %s items\n' "$(basename "$d")" "${n:-0}"
  done
}

do_sw() {
  local payload
  payload=$(cat <<'JS'
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil((async () => {
  for (const k of await caches.keys()) await caches.delete(k);
  await self.registration.unregister();
  for (const c of await self.clients.matchAll()) c.navigate(c.url);
})()));
JS
)
  local n=0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if printf '%s\n' "$payload" > "$f" 2>/dev/null; then
      echo "${GRN}replaced${OFF} $f"
      n=$((n+1))
    else
      echo "${RED}FAILED${OFF}   $f"
    fi
  done < <(find "$ROOT" -type f \( -name 'nochain-sw.js' -o -name 'nc-sw.js' -o -path '*/nochain/sw.js' \) 2>/dev/null)
  [ "$n" -eq 0 ] && echo "No nochain service worker files found."
  echo
  echo "Leave these in place for at least 30 days, then delete them."
}

# --------------------------------------------------------------------------

case "$MODE" in
  list)    do_list ;;
  restore) do_restore ;;
  sw)      do_sw ;;
  scan)    scan_all; summarise ;;
  quarantine)
    scan_all; summarise
    echo
    read -r -p "Move all HIGH findings to ${QROOT}? [y/N] " ans
    case "$ans" in y|Y|yes|YES) do_quarantine ;; *) echo "Nothing moved." ;; esac
    ;;
  delete)
    scan_all; summarise
    do_delete
    ;;
esac
