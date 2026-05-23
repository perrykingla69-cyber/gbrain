#!/usr/bin/env bash
# v0.40 D15.4 CI guard — prevent webhook_secret leak through sources.config
# serialization paths.
#
# After v0.40, sources.config can contain secrets (webhook_secret). Any code
# path that returns the raw config object via JSON.stringify / serializer
# without first running it through redactSourceConfig() will leak the secret.
#
# This script greps for risky patterns:
#   1. JSON.stringify on a `config` field where the source is a row from `sources`
#   2. New endpoints / ops that return raw `config` without `redactSourceConfig`
#
# Failure mode is loose-positive on purpose — false positives cost one
# 30-second comment-or-fix; false negatives leak production secrets.

set -euo pipefail

cd "$(dirname "$0")/.."

FOUND=0

# Pattern A: sources.config field referenced in a JSON serializer call site
# without redactSourceConfig nearby. Covers MCP op handlers, admin API
# routes, sources.ts subcommands that print --json output.
#
# Whitelist:
#   - src/core/source-config-redact.ts itself (defines the redactor)
#   - src/core/sources-load.ts (returns raw rows; callers redact)
#   - src/commands/sources.ts runFederate/runWebhook* (mutators write raw)
#   - src/core/migrate.ts (DDL data references not serialization)
#   - src/core/sources-ops.ts (CLI feedback prints structured fields, not raw config)
#   - test/ (tests are allowed to introspect raw config)

# Grep for `r.config\|src.config\|source.config` near JSON.stringify/console.log/res.json
# where redactSourceConfig is NOT used in the same hunk.
RAW_PATTERN='\b(\.config\b|config:[[:space:]]*src\.config)\b'

if command -v rg >/dev/null 2>&1; then
  GREP="rg"
else
  GREP="grep -rE"
fi

CANDIDATES=$($GREP -n \
  -e 'JSON\.stringify\(.*config' \
  -e 'res\.json\(.*config' \
  -e 'res\.json\(\{[^}]*\.config' \
  -e 'console\.log\(JSON\.stringify\(.*config' \
  --include='*.ts' \
  src/ 2>/dev/null || true)

# Filter out files we trust
FILTERED=$(echo "$CANDIDATES" | \
  grep -v 'src/core/source-config-redact.ts' | \
  grep -v 'src/core/sources-load.ts' | \
  grep -v 'src/commands/sources.ts' | \
  grep -v 'src/core/migrate.ts' | \
  grep -v 'src/core/sources-ops.ts' || true)

if [ -n "$FILTERED" ]; then
  # For each candidate, check if redactSourceConfig appears within 10 lines above.
  while IFS= read -r LINE; do
    [ -z "$LINE" ] && continue
    FILE=$(echo "$LINE" | cut -d: -f1)
    LINENO=$(echo "$LINE" | cut -d: -f2)
    # Look in surrounding 20 lines
    START=$((LINENO - 10))
    [ "$START" -lt 1 ] && START=1
    END=$((LINENO + 5))
    CONTEXT=$(sed -n "${START},${END}p" "$FILE" 2>/dev/null || true)
    if ! echo "$CONTEXT" | grep -q 'redactSourceConfig'; then
      echo "POTENTIAL_LEAK: $LINE"
      echo "  Context lacks redactSourceConfig — verify webhook_secret cannot be serialized."
      FOUND=1
    fi
  done <<< "$FILTERED"
fi

if [ "$FOUND" -eq 1 ]; then
  echo ""
  echo "v0.40 D15.4 guard: every sources.config serializer MUST go through"
  echo "redactSourceConfig() from src/core/source-config-redact.ts."
  echo ""
  echo "If a flagged site is a known false positive (e.g. CLI command that"
  echo "only prints metadata, not the raw object), update the whitelist in"
  echo "scripts/check-source-config-leak.sh."
  exit 1
fi

exit 0
