#!/bin/bash
#
# ai-code-guard — GitHub Action entrypoint
# Scans changed files for AI-specific vulnerabilities.
#
set -euo pipefail

GITHUB_TOKEN="${1:-$GITHUB_TOKEN}"
FAIL_SEVERITY="${2:-high}"
MODE="${3:-pr}"
CONFIG_PATH="${4:-}"
SEMGREP_RULES="${5:-}"
EXCLUDE_PATTERNS="${6:-*.min.js,*.bundle.js,*.pb.go,vendor/*,node_modules/*}"

echo "::group::ai-code-guard setup"
echo "Mode: $MODE"
echo "Fail severity: $FAIL_SEVERITY"
echo "Working directory: $(pwd)"
echo "Repository: ${GITHUB_REPOSITORY:-unknown}"
echo "::endgroup::"

# --- Step 1: Determine which files to scan ---
SCAN_DIR="/tmp/ai-code-guard-scan"
mkdir -p "$SCAN_DIR"
REPORT_FILE="/tmp/ai-code-guard-report.json"
ALL_FINDINGS="[]"

if [ "$MODE" = "pr" ] && [ -n "${GITHUB_EVENT_PATH:-}" ]; then
  echo "::group::Extracting PR diff files"
  # Get changed files from the GitHub event payload
  PR_NUMBER=$(jq -r '.pull_request.number // .issue.number // empty' "$GITHUB_EVENT_PATH")
  if [ -n "$PR_NUMBER" ]; then
    echo "PR #$PR_NUMBER detected, fetching changed files..."
    CHANGED_FILES=$(jq -r '
      .pull_request.changed_files as $total |
      if $total and $total > 0 then
        # Use the API to get full list if available
        empty
      else
        # Fall back to git diff
        empty
      end
    ' "$GITHUB_EVENT_PATH" 2>/dev/null || true)

    # Build list of changed files from the event
    jq -r '
      .pull_request.head.sha as $head |
      .pull_request.base.sha as $base |
      empty
    ' "$GITHUB_EVENT_PATH" 2>/dev/null || true
  fi
  # Use git to get changed files against HEAD~1 (typical PR context)
  FILES_TO_SCAN=$(git diff --name-only --diff-filter=AM HEAD~1 2>/dev/null || git diff --name-only HEAD~1 2>/dev/null || echo "")
  echo "::endgroup::"
else
  echo "Full repo scan mode (or PR context unavailable)"
  FILES_TO_SCAN=$(find . -type f \( -name '*.js' -o -name '*.ts' -o -name '*.py' -o -name '*.go' -o -name '*.rs' -o -name '*.java' -o -name '*.rb' -o -name '*.sh' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' -o -name '*.tf' \) 2>/dev/null | head -500)
fi

# Apply exclusion patterns
IFS=',' read -ra EXCLUDE <<< "$EXCLUDE_PATTERNS"
for pattern in "${EXCLUDE[@]}"; do
  FILES_TO_SCAN=$(echo "$FILES_TO_SCAN" | grep -v "$pattern" 2>/dev/null || true)
done

echo "Files to scan: $(echo "$FILES_TO_SCAN" | wc -l)"

if [ -z "$FILES_TO_SCAN" ]; then
  echo "No files to scan. Skipping."
  echo '{"summary":{"scanned":0,"vulnerabilities":0,"failures":0},"findings":[],"safe":true}' > "$REPORT_FILE"
  echo "count=0" >> "$GITHUB_OUTPUT"
  echo "report=$REPORT_FILE" >> "$GITHUB_OUTPUT"
  exit 0
fi

# --- Step 2: Run the Node.js scanner (ai-specific rules) ---
echo "::group::Running AI-specific vulnerability scanner"
node /action/scanner/index.js \
  --files "$(echo "$FILES_TO_SCAN" | tr '\n' ',')" \
  --workdir "$(pwd)" \
  --report "$REPORT_FILE" \
  --fail-severity "$FAIL_SEVERITY"
SCANNER_EXIT=$?
echo "Scanner exit code: $SCANNER_EXIT"
echo "::endgroup::"

# --- Step 3: Run Semgrep with custom rules ---
echo "::group::Running Semgrep AI-security rules"
declare -a SEMGREP_ARGS
SEMGREP_ARGS=(
  --config "/action/semgrep-rules/"
  --json
  --no-error
  --quiet
  --output /tmp/semgrep-results.json
)

# Add custom rules if provided
if [ -n "$SEMGREP_RULES" ]; then
  IFS=',' read -ra RULES <<< "$SEMGREP_RULES"
  for rule in "${RULES[@]}"; do
    if [ -f "$(pwd)/$rule" ]; then
      SEMGREP_ARGS+=(--config "$(pwd)/$rule")
    fi
  done
fi

semgrep scan "${SEMGREP_ARGS[@]}" $(echo "$FILES_TO_SCAN")
echo "::endgroup::"

# --- Step 4: Combine results ---
echo "::group::Consolidating results"
node /action/scanner/consolidate.js \
  --scanner-report "$REPORT_FILE" \
  --semgrep-report /tmp/semgrep-results.json \
  --output "$REPORT_FILE" \
  --fail-severity "$FAIL_SEVERITY"
CONSOLIDATE_EXIT=$?
echo "::endgroup::"

# --- Step 5: Post PR comments (if in PR mode) ---
if [ "$MODE" = "pr" ] && [ -n "$GITHUB_TOKEN" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  echo "::group::Posting PR comments"
  node /action/scanner/post-comments.js \
    --report "$REPORT_FILE" \
    --token "$GITHUB_TOKEN" \
    --repo "${GITHUB_REPOSITORY}" \
    --pr "${PR_NUMBER:-$(jq -r '.pull_request.number // .issue.number // "0"' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "0")}"
  echo "::endgroup::"
fi

# --- Step 6: Output results ---
FINDING_COUNT=$(jq '.summary.vulnerabilities // 0' "$REPORT_FILE")
echo "count=$FINDING_COUNT" >> "$GITHUB_OUTPUT"
echo "report=$REPORT_FILE" >> "$GITHUB_OUTPUT"

echo "Scan complete. Vulnerabilities found: $FINDING_COUNT"

# Fail action if critical/high severity findings and fail-severity is set
if [ "$FAIL_SEVERITY" != "none" ]; then
  FAIL_COUNT=$(jq '.summary.failures // 0' "$REPORT_FILE")
  if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "::error::$FAIL_COUNT vulnerability(ies) at severity '$FAIL_SEVERITY' or above. Failing check."
    exit 1
  fi
fi

exit 0
