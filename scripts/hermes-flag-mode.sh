#!/usr/bin/env bash
set -euo pipefail

BASE="${HERMES_FLAG_BASE:-/root/.hermes/redteam-flag-mode}"
CASE=""
TARGET=""
ACTION="init"
FLAG=""
NOTE=""
FILE=""

usage() {
  cat <<'EOF'
Hermes Red-Team Flag Mode helper.

Usage:
  hermes-flag-mode.sh init --case NAME [--target TARGET]
  hermes-flag-mode.sh status --case NAME
  hermes-flag-mode.sh add-flag --case NAME --target TARGET --flag FLAG [--note NOTE]
  hermes-flag-mode.sh add-evidence --case NAME --file PATH [--note NOTE]
  hermes-flag-mode.sh ledger --case NAME

This helper only manages local workspace/evidence/ledger. It does not attack targets.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    init|status|add-flag|add-evidence|ledger) ACTION="$1"; shift ;;
    --case) CASE="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --flag) FLAG="${2:-}"; shift 2 ;;
    --note) NOTE="${2:-}"; shift 2 ;;
    --file) FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$CASE" ]] || { echo "--case required" >&2; exit 2; }
CASE_SAFE=$(printf '%s' "$CASE" | tr -c 'A-Za-z0-9_.-' '_')
DIR="$BASE/cases/$CASE_SAFE"
LEDGER="$DIR/flags.tsv"
META="$DIR/meta.txt"
EVID="$DIR/evidence"
TS=$(date -Is)

mkdir -p "$DIR" "$EVID"

case "$ACTION" in
  init)
    if [[ ! -f "$LEDGER" ]]; then
      printf 'timestamp\ttarget\tflag_sha256\tflag_preview\tnote\n' > "$LEDGER"
      chmod 600 "$LEDGER"
    fi
    {
      echo "case=$CASE_SAFE"
      echo "created_or_seen=$TS"
      [[ -n "$TARGET" ]] && echo "target=$TARGET"
      echo "base=$DIR"
    } >> "$META"
    echo "case_dir=$DIR"
    echo "ledger=$LEDGER"
    echo "evidence_dir=$EVID"
    ;;
  status)
    echo "case_dir=$DIR"
    echo "ledger_exists=$([[ -f "$LEDGER" ]] && echo yes || echo no)"
    echo "evidence_count=$(find "$EVID" -type f 2>/dev/null | wc -l)"
    echo "flags_count=$([[ -f "$LEDGER" ]] && tail -n +2 "$LEDGER" | wc -l || echo 0)"
    ;;
  add-flag)
    [[ -n "$TARGET" && -n "$FLAG" ]] || { echo "--target and --flag required" >&2; exit 2; }
    [[ -f "$LEDGER" ]] || printf 'timestamp\ttarget\tflag_sha256\tflag_preview\tnote\n' > "$LEDGER"
    HASH=$(printf '%s' "$FLAG" | sha256sum | awk '{print $1}')
    if [[ ${#FLAG} -gt 14 ]]; then
      PREVIEW="${FLAG:0:6}...${FLAG: -4}"
    else
      PREVIEW="$FLAG"
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$TS" "$TARGET" "$HASH" "$PREVIEW" "$NOTE" >> "$LEDGER"
    chmod 600 "$LEDGER"
    echo "flag_recorded=1"
    echo "flag_sha256=$HASH"
    ;;
  add-evidence)
    [[ -n "$FILE" && -f "$FILE" ]] || { echo "--file must exist" >&2; exit 2; }
    DEST="$EVID/$(date +%Y%m%d_%H%M%S)_$(basename "$FILE")"
    cp -a "$FILE" "$DEST"
    printf '%s\t%s\t%s\n' "$TS" "$DEST" "$NOTE" >> "$DIR/evidence.tsv"
    echo "evidence=$DEST"
    ;;
  ledger)
    [[ -f "$LEDGER" ]] && cat "$LEDGER" || echo "no ledger"
    ;;
esac
