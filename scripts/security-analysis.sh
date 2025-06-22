#!/usr/bin/env bash
# Main WASM Security Analysis Script for Golem LLM
set -uo pipefail  # Removed -e to continue on errors

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()     { echo -e "${BLUE}[SECURITY]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; }
error()   { echo -e "${RED}[CRITICAL]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Global counters for final summary
GLOBAL_CRITICAL=0
GLOBAL_WARNINGS=0
GLOBAL_ANALYZED=0

# Ensure required tools are available
check_tools() {
  local missing_tools=()
  
  for tool in wasm-validate wasm-objdump; do
    if ! command -v "$tool" &>/dev/null; then
      missing_tools+=("$tool")
    fi
  done
  
  if [ ${#missing_tools[@]} -gt 0 ]; then
    error "Missing required tools: ${missing_tools[*]}"
    error "Please install WABT (https://github.com/WebAssembly/wabt)"
    return 1
  fi
  
  return 0
}

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
  local wasm_valid="unknown"
  if [ -f "$wasm_file" ]; then
    if wasm-validate "$wasm_file" &>/dev/null; then
      success "✅ $component_name: Valid WASM structure"
      wasm_valid="passed"
    else
      error "❌ $component_name: Invalid WASM structure"
      critical_issues=$((critical_issues + 1))
      wasm_valid="failed"
    fi
  else
    error "❌ $component_name: File not found"
    critical_issues=$((critical_issues + 1))
    wasm_valid="file_not_found"
  fi

  # 2) File size (bytes) - handle missing files gracefully
  local file_size=0
  local size_mb=0
  if [ -f "$wasm_file" ]; then
    file_size=$(wc -c < "$wasm_file" 2>/dev/null | tr -d ' ' || echo "0")
    size_mb=$(( file_size / 1024 / 1024 ))
  fi

  # 3) Dump for imports/exports & code analysis - only if file exists and is valid
  local dump=""
  if [ -f "$wasm_file" ] && [ "$wasm_valid" = "passed" ]; then
    dump=$(wasm-objdump -x -d "$wasm_file" 2>/dev/null || echo "")
  fi

  # 4) Dangerous imports
  local dangerous_imports=0
  if [ -n "$dump" ]; then
    dangerous_imports=$(echo "$dump" | grep -i import | grep -cE "(filesystem|process|exec|syscall|raw_memory|kernel|shell)" 2>/dev/null || echo "0")
    if [ "$dangerous_imports" -gt 0 ]; then
      error "🚨 $dangerous_imports dangerous system imports in $component_name"
      critical_issues=$((critical_issues + dangerous_imports))
    fi
  fi

  # 5) Network imports (informational)
  local network_imports=0
  if [ -n "$dump" ]; then
    network_imports=$(echo "$dump" | grep -i import | grep -cE "(http|tcp|socket|fetch|request|url|net)" 2>/dev/null || echo "0")
    if [ "$network_imports" -gt 0 ]; then
      log "ℹ️ $network_imports network imports in $component_name (expected)"
      info_count=$((info_count + network_imports))
    fi
  fi

  # 6) Sensitive exports
  local sensitive_exports=0
  if [ -n "$dump" ]; then
    sensitive_exports=$(echo "$dump" | grep -i export | grep -cE "(key|secret|token|password|credential|auth|private)" 2>/dev/null || echo "0")
    if [ "$sensitive_exports" -gt 0 ]; then
      error "🚨 $sensitive_exports potentially sensitive exports in $component_name"
      critical_issues=$((critical_issues + sensitive_exports))
    fi
  fi

  # 7) Debug/internal exports
  local debug_exports=0
  if [ -n "$dump" ]; then
    debug_exports=$(echo "$dump" | grep -i export | grep -cE "(debug|internal|test|dev|trace)" 2>/dev/null || echo "0")
    if [ "$debug_exports" -gt 0 ]; then
      warn "⚠️ $debug_exports debug/internal exports in $component_name"
      warnings=$((warnings + debug_exports))
    fi
  fi

  # 8) Code-level analysis: memory.grow, indirect calls
  local memory_grows=0
  local indirect_calls=0
  if [ -n "$dump" ]; then
    memory_grows=$(echo "$dump" | grep -c "memory.grow" 2>/dev/null || echo "0")
    if [ "$memory_grows" -gt 5 ]; then
      warn "⚠️ $memory_grows memory.grow operations in $component_name (DoS risk)"
      warnings=$((warnings + 1))
    fi

    indirect_calls=$(echo "$dump" | grep -c "call_indirect" 2>/dev/null || echo "0")
    if [ "$indirect_calls" -gt 10 ]; then
      warn "⚠️ $indirect_calls indirect calls in $component_name (review control flow)"
      warnings=$((warnings + 1))
    fi
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
  [ "$wasm_valid" = "failed" ]     && recs+=('"Fix WASM structure validation errors"')
  recs+=(
    '"Implement comprehensive input validation"'
    '"Add rate limiting for resource-intensive operations"'
    '"Regular security audits and dependency updates"'
  )
  local rec_json
  rec_json=$(IFS=, ; echo "[${recs[*]}]")

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
  "recommendations": $rec_json
}
EOF

  # Report summary line
  case "$risk_level" in
    "CRITICAL") error "🚨 $component_name: CRITICAL risk ($critical_issues critical, $warnings warnings)" ;;
    "HIGH")     warn  "⚠️ $component_name: HIGH risk ($critical_issues critical, $warnings warnings)" ;;
    "MEDIUM")   warn  "⚠️ $component_name: MEDIUM risk ($critical_issues critical, $warnings warnings)" ;;
    *)          success "✅ $component_name: LOW risk ($critical_issues critical, $warnings warnings)" ;;
  esac

  # Update global counters
  GLOBAL_CRITICAL=$((GLOBAL_CRITICAL + critical_issues))
  GLOBAL_WARNINGS=$((GLOBAL_WARNINGS + warnings))
  GLOBAL_ANALYZED=$((GLOBAL_ANALYZED + 1))

  return 0  # Always return success to continue analysis
}

# Generate summary report for GitHub Actions
generate_summary() {
  local summary_file="security-summary.json"
  
  # Collect all component reports
  local components_json="[]"
  if ls *-security-analysis.json 1> /dev/null 2>&1; then
    components_json=$(jq -s '.' *-security-analysis.json 2>/dev/null || echo "[]")
  fi
  
  # Count components by risk level
  local critical_count=$(echo "$components_json" | jq '[.[] | select(.risk_level == "CRITICAL")] | length' 2>/dev/null || echo "0")
  local high_count=$(echo "$components_json" | jq '[.[] | select(.risk_level == "HIGH")] | length' 2>/dev/null || echo "0")
  local medium_count=$(echo "$components_json" | jq '[.[] | select(.risk_level == "MEDIUM")] | length' 2>/dev/null || echo "0")
  local low_count=$(echo "$components_json" | jq '[.[] | select(.risk_level == "LOW")] | length' 2>/dev/null || echo "0")
  
  cat > "$summary_file" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_components": $GLOBAL_ANALYZED,
  "total_critical_issues": $GLOBAL_CRITICAL,
  "total_warnings": $GLOBAL_WARNINGS,
  "risk_distribution": {
    "critical": $critical_count,
    "high": $high_count,
    "medium": $medium_count,
    "low": $low_count
  },
  "components": $components_json
}
EOF

  log "📊 Summary report generated: $summary_file"
}

# Main entrypoint
main() {
  log "🚀 Starting Golem LLM WASM Security Analysis"
  log "============================================"

  # Check tools first, but don't exit on failure
  if ! check_tools; then
    warn "⚠️ Some security tools are missing - analysis may be limited"
  fi

  # Iterate debug builds
  if [ -d "components/debug" ]; then
    log "📋 Analyzing debug components..."
    for file in components/debug/*.wasm; do
      [ -f "$file" ] && analyze_component "$file" "$(basename "$file" .wasm)-debug"
    done
  else
    warn "⚠️ No debug components directory found"
  fi

  # Iterate release builds
  if [ -d "components/release" ]; then
    log "📋 Analyzing release components..."
    for file in components/release/*.wasm; do
      [ -f "$file" ] && analyze_component "$file" "$(basename "$file" .wasm)-release"
    done
  else
    warn "⚠️ No release components directory found"
  fi

  # Check for any WASM files in current directory as fallback
  if [ "$GLOBAL_ANALYZED" -eq 0 ]; then
    log "📋 Searching for WASM files in current directory..."
    for file in *.wasm; do
      [ -f "$file" ] && analyze_component "$file" "$(basename "$file" .wasm)"
    done
  fi

  # Generate summary report
  generate_summary

  # Final summary
  log "📊 SECURITY ANALYSIS COMPLETE"
  log "============================="
  log "Components analyzed: $GLOBAL_ANALYZED"
  log "Total critical issues: $GLOBAL_CRITICAL"
  log "Total warnings: $GLOBAL_WARNINGS"

  if [ "$GLOBAL_ANALYZED" -eq 0 ]; then
    warn "⚠️ No components found to analyze – check build output"
  fi

  # Always exit successfully - let GitHub Actions handle the decision
  success "✅ Security analysis completed"
  exit 0
}

main "$@"