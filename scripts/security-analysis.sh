#!/usr/bin/env bash
# Main WASM Security Analysis Script for Golem LLM
set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()     { echo -e "${BLUE}[SECURITY]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; }
error()   { echo -e "${RED}[CRITICAL]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Ensure required tools are available
for tool in wasm-validate wasm-objdump; do
  if ! command -v "$tool" &>/dev/null; then
    error "$tool not found. Please install WABT (https://github.com/WebAssembly/wabt)."
    exit 1
  fi
done

# Analyze one WASM file
analyze_component() {
  local wasm_file="$1"
  local component_name="$2"
  local report_file="${component_name}-security-analysis.json"

  log "🔍 Analyzing $component_name..."

  # Metrics
  local critical_issues=0
  local warnings=0
  local info_count=0

  # 1) Validate WASM structure
  if wasm-validate "$wasm_file" &>/dev/null; then
    success "✅ $component_name: Valid WASM structure"
    wasm_valid="passed"
  else
    error "❌ $component_name: Invalid WASM structure"
    critical_issues=$((critical_issues + 1))
    wasm_valid="failed"
  fi

  # 2) File size (bytes) via wc -c
  local file_size
  file_size=$(wc -c < "$wasm_file" | tr -d ' ')
  local size_mb=$(( file_size / 1024 / 1024 ))

  # 3) Dump for imports/exports & code analysis
  local dump
  dump=$(wasm-objdump -x -d "$wasm_file" 2>/dev/null || echo "")

  # 4) Dangerous imports
  local dangerous_imports
  dangerous_imports=$(echo "$dump" | grep -i import | grep -icE "(filesystem|process|exec|syscall|raw_memory|kernel|shell)" || echo 0)
  if [ "$dangerous_imports" -gt 0 ]; then
    error "🚨 $dangerous_imports dangerous system imports in $component_name"
    critical_issues=$((critical_issues + dangerous_imports))
  fi

  # 5) Network imports (informational)
  local network_imports
  network_imports=$(echo "$dump" | grep -i import | grep -icE "(http|tcp|socket|fetch|request|url|net)" || echo 0)
  if [ "$network_imports" -gt 0 ]; then
    log "ℹ️ $network_imports network imports in $component_name (expected)"
    info_count=$((info_count + network_imports))
  fi

  # 6) Sensitive exports
  local sensitive_exports
  sensitive_exports=$(echo "$dump" | grep -i export | grep -icE "(key|secret|token|password|credential|auth|private)" || echo 0)
  if [ "$sensitive_exports" -gt 0 ]; then
    error "🚨 $sensitive_exports potentially sensitive exports in $component_name"
    critical_issues=$((critical_issues + sensitive_exports))
  fi

  # 7) Debug/internal exports
  local debug_exports
  debug_exports=$(echo "$dump" | grep -i export | grep -icE "(debug|internal|test|dev|trace)" || echo 0)
  if [ "$debug_exports" -gt 0 ]; then
    warn "⚠️ $debug_exports debug/internal exports in $component_name"
    warnings=$((warnings + debug_exports))
  fi

  # 8) Code-level analysis: memory.grow, indirect calls
  local memory_grows
  memory_grows=$(echo "$dump" | grep -c "memory.grow" || echo 0)
  if [ "$memory_grows" -gt 5 ]; then
    warn "⚠️ $memory_grows memory.grow operations in $component_name (DoS risk)"
    warnings=$((warnings + 1))
  fi

  local indirect_calls
  indirect_calls=$(echo "$dump" | grep -c "call_indirect" || echo 0)
  if [ "$indirect_calls" -gt 10 ]; then
    warn "⚠️ $indirect_calls indirect calls in $component_name (review control flow)"
    warnings=$((warnings + 1))
  fi

  # 9) Size warning
  if [ "$size_mb" -gt 10 ]; then
    warn "⚠️ Large component size (${size_mb}MB) in $component_name"
    warnings=$((warnings + 1))
  fi

  # Determine risk level
  local risk_level="LOW"
  if [ "$critical_issues" -gt 0 ]; then
    risk_level="CRITICAL"
  elif [ "$warnings" -gt 3 ]; then
    risk_level="HIGH"
  elif [ "$warnings" -gt 0 ]; then
    risk_level="MEDIUM"
  fi

  # Build recommendations array safely
  local recs=()
  [ "$critical_issues" -gt 0 ]     && recs+=('"Address critical security issues immediately"')
  [ "$sensitive_exports" -gt 0 ]   && recs+=('"Remove or secure sensitive data exports"')
  [ "$warnings" -gt 2 ]            && recs+=('"Review and address warning-level issues"')
  recs+=(
    '"Implement comprehensive input validation"'
    '"Add rate limiting for resource-intensive operations"'
    '"Regular security audits and dependency updates"'
  )
  local rec_json
  rec_json=$(IFS=, ; echo "${recs[*]}")

  # Emit JSON report
  cat > "$report_file" << EOF
{
  "component": "$component_name",
  "file_path": "$wasm_file",
  "file_size_bytes": $file_size,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "risk_level": "$risk_level",
  "summary": {
    "critical_issues": $critical_issues,
    "warnings": $warnings,
    "info_items": $info_count
  },
  "analysis": {
    "wasm_validation": "$wasm_valid",
    "dangerous_imports": $dangerous_imports,
    "network_imports": $network_imports,
    "sensitive_exports": $sensitive_exports,
    "debug_exports": $debug_exports,
    "memory_grows": $memory_grows,
    "indirect_calls": $indirect_calls,
    "component_size_mb": $size_mb
  },
  "recommendations": [ $rec_json ]
}
EOF

  # Report summary line
  case "$risk_level" in
    "CRITICAL") error "🚨 $component_name: CRITICAL risk ($critical_issues critical, $warnings warnings)" ;;
    "HIGH")     warn  "⚠️ $component_name: HIGH risk ($critical_issues critical, $warnings warnings)" ;;
    "MEDIUM")   warn  "⚠️ $component_name: MEDIUM risk ($critical_issues critical, $warnings warnings)" ;;
    *)          success "✅ $component_name: LOW risk ($critical_issues critical, $warnings warnings)" ;;
  esac

  return "$critical_issues"
}

# Main entrypoint
main() {
  log "🚀 Starting Golem LLM WASM Security Analysis"
  log "============================================"

  local total_critical=0
  local count=0

  # Iterate debug builds
  if [ -d "components/debug" ]; then
    log "📋 Analyzing debug components..."
    for file in components/debug/*.wasm; do
      [ -f "$file" ] || continue
      analyze_component "$file" "$(basename "$file" .wasm)-debug"
      total_critical=$(( total_critical + $? ))
      count=$(( count + 1 ))
    done
  else
    warn "⚠️ No debug components directory found"
  fi

  # Iterate release builds
  if [ -d "components/release" ]; then
    log "📋 Analyzing release components..."
    for file in components/release/*.wasm; do
      [ -f "$file" ] || continue
      analyze_component "$file" "$(basename "$file" .wasm)-release"
      total_critical=$(( total_critical + $? ))
      count=$(( count + 1 ))
    done
  else
    warn "⚠️ No release components directory found"
  fi

  # Final summary
  log "📊 SECURITY ANALYSIS COMPLETE"
  log "============================="
  log "Components analyzed: $count"
  log "Total critical issues: $total_critical"

  if [ "$count" -eq 0 ]; then
    warn "⚠️ No components found to analyze – check build output"
    exit 1
  fi

  if [ "$total_critical" -gt 0 ]; then
    error "❌ CRITICAL security issues found – immediate attention required"
    exit 1
  else
    success "✅ Security analysis completed successfully"
    exit 0
  fi
}

main "$@"
