#!/bin/bash
# Main WASM Security Analysis Script for Golem LLM
set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${BLUE}[SECURITY]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; }
error() { echo -e "${RED}[CRITICAL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Function to analyze a single WASM component
analyze_component() {
    local wasm_file="$1"
    local component_name="$2"
    local report_file="${component_name}-security-analysis.json"
    
    log "🔍 Analyzing $component_name..."
    
    # Initialize security metrics
    local critical_issues=0
    local warnings=0
    local info_count=0
    
    # Basic WASM validation
    local wasm_valid="failed"
    if wasm-validate "$wasm_file" 2>/dev/null; then
        wasm_valid="passed"
        success "✅ $component_name: Valid WASM structure"
    else
        error "❌ $component_name: Invalid WASM structure"
        critical_issues=$((critical_issues + 1))
    fi
    
    # Get file metadata
    local file_size=$(stat -c%s "$wasm_file" 2>/dev/null || stat -f%z "$wasm_file")
    local size_mb=$((file_size / 1024 / 1024))
    
    # Analyze WASM structure using objdump
    local analysis_output=""
    if command -v wasm-objdump >/dev/null 2>&1; then
        analysis_output=$(wasm-objdump -x "$wasm_file" 2>/dev/null || echo "")
    fi
    
    # Security Analysis: Dangerous Imports
    local dangerous_imports=0
    if [ -n "$analysis_output" ]; then
        dangerous_imports=$(echo "$analysis_output" | grep -i import | grep -icE "(filesystem|process|exec|syscall|raw_memory|kernel|shell)" || echo "0")
        if [ "$dangerous_imports" -gt 0 ]; then
            error "🚨 $dangerous_imports dangerous system imports in $component_name"
            critical_issues=$((critical_issues + dangerous_imports))
            echo "$analysis_output" | grep -i import | grep -iE "(filesystem|process|exec|syscall|raw_memory|kernel|shell)" || true
        fi
    fi
    
    # Security Analysis: Network Imports (expected for LLM providers)
    local network_imports=0
    if [ -n "$analysis_output" ]; then
        network_imports=$(echo "$analysis_output" | grep -i import | grep -icE "(http|tcp|socket|fetch|request|url|net)" || echo "0")
        if [ "$network_imports" -gt 0 ]; then
            log "ℹ️ $network_imports network imports in $component_name (expected for LLM providers)"
            info_count=$((info_count + 1))
        fi
    fi
    
    # Security Analysis: Sensitive Exports
    local sensitive_exports=0
    if [ -n "$analysis_output" ]; then
        sensitive_exports=$(echo "$analysis_output" | grep -i export | grep -icE "(key|secret|token|password|credential|auth|private)" || echo "0")
        if [ "$sensitive_exports" -gt 0 ]; then
            error "🚨 $sensitive_exports potentially sensitive exports in $component_name"
            critical_issues=$((critical_issues + sensitive_exports))
            echo "$analysis_output" | grep -i export | grep -iE "(key|secret|token|password|credential|auth|private)" || true
        fi
    fi
    
    # Security Analysis: Debug/Internal Exports
    local debug_exports=0
    if [ -n "$analysis_output" ]; then
        debug_exports=$(echo "$analysis_output" | grep -i export | grep -icE "(debug|internal|test|dev|trace)" || echo "0")
        if [ "$debug_exports" -gt 0 ]; then
            warn "⚠️ $debug_exports debug/internal exports in $component_name"
            warnings=$((warnings + debug_exports))
        fi
    fi
    
    # Code Analysis: Memory Operations
    local memory_grows=0
    local memory_ops=0
    local indirect_calls=0
    
    if command -v wasm-objdump >/dev/null 2>&1; then
        local code_analysis=$(wasm-objdump -d "$wasm_file" 2>/dev/null || echo "")
        if [ -n "$code_analysis" ]; then
            memory_grows=$(echo "$code_analysis" | grep -c "memory.grow" || echo "0")
            memory_ops=$(echo "$code_analysis" | grep -cE "(memory\.(copy|fill))" || echo "0")
            indirect_calls=$(echo "$code_analysis" | grep -c "call_indirect" || echo "0")
            
            if [ "$memory_grows" -gt 5 ]; then
                warn "⚠️ $memory_grows memory.grow operations in $component_name (potential DoS risk)"
                warnings=$((warnings + 1))
            fi
            
            if [ "$indirect_calls" -gt 10 ]; then
                warn "⚠️ $indirect_calls indirect calls in $component_name (review control flow)"
                warnings=$((warnings + 1))
            fi
        fi
    fi
    
    # Component Size Analysis
    if [ "$size_mb" -gt 10 ]; then
        warn "⚠️ Large component size (${size_mb}MB) in $component_name"
        warnings=$((warnings + 1))
    fi
    
    # Determine overall risk level
    local risk_level="LOW"
    if [ "$critical_issues" -gt 0 ]; then
        risk_level="CRITICAL"
    elif [ "$warnings" -gt 3 ]; then
        risk_level="HIGH"
    elif [ "$warnings" -gt 0 ]; then
        risk_level="MEDIUM"
    fi
    
    # Generate comprehensive JSON report
    cat > "$report_file" << JSON_EOF
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
        "memory_operations": $memory_ops,
        "indirect_calls": $indirect_calls,
        "component_size_mb": $size_mb
    },
    "recommendations": [
        $([ "$critical_issues" -gt 0 ] && echo '"Address critical security issues immediately",' || echo "")
        $([ "$sensitive_exports" -gt 0 ] && echo '"Remove or secure sensitive data exports",' || echo "")
        $([ "$warnings" -gt 2 ] && echo '"Review and address warning-level issues",' || echo "")
        "Implement comprehensive input validation",
        "Add rate limiting for resource-intensive operations",
        "Regular security audits and dependency updates"
    ]
}
JSON_EOF

    # Clean up trailing commas in JSON
    sed -i 's/,]/]/g' "$report_file" 2>/dev/null || sed -i '' 's/,]/]/g' "$report_file" 2>/dev/null || true
    
    # Report component analysis results
    case "$risk_level" in
        "CRITICAL") error "🚨 $component_name: CRITICAL risk ($critical_issues critical, $warnings warnings)" ;;
        "HIGH") warn "⚠️ $component_name: HIGH risk ($critical_issues critical, $warnings warnings)" ;;
        "MEDIUM") warn "⚠️ $component_name: MEDIUM risk ($critical_issues critical, $warnings warnings)" ;;
        *) success "✅ $component_name: LOW risk ($critical_issues critical, $warnings warnings)" ;;
    esac
    
    return $critical_issues
}

# Main execution
main() {
    log "🚀 Starting Golem LLM WASM Security Analysis"
    log "============================================"
    
    local total_critical=0
    local components_analyzed=0
    
    # Analyze debug components
    if [ -d "components/debug" ]; then
        log "📋 Analyzing debug components..."
        for wasm_file in components/debug/*.wasm; do
            if [ -f "$wasm_file" ]; then
                component_name=$(basename "$wasm_file" .wasm)
                analyze_component "$wasm_file" "${component_name}-debug"
                total_critical=$((total_critical + $?))
                components_analyzed=$((components_analyzed + 1))
            fi
        done
    else
        warn "⚠️ No debug components directory found"
    fi
    
    # Analyze release components
    if [ -d "components/release" ]; then
        log "📋 Analyzing release components..."
        for wasm_file in components/release/*.wasm; do
            if [ -f "$wasm_file" ]; then
                component_name=$(basename "$wasm_file" .wasm)
                analyze_component "$wasm_file" "${component_name}-release"
                total_critical=$((total_critical + $?))
                components_analyzed=$((components_analyzed + 1))
            fi
        done
    else
        warn "⚠️ No release components directory found"
    fi
    
    # Final summary
    log "📊 SECURITY ANALYSIS COMPLETE"
    log "============================="
    log "Components analyzed: $components_analyzed"
    log "Total critical issues: $total_critical"
    
    if [ "$total_critical" -gt 0 ]; then
        error "❌ CRITICAL security issues found - immediate attention required"
        return 1
    elif [ "$components_analyzed" -eq 0 ]; then
        warn "⚠️ No components found to analyze - check build process"
        return 1
    else
        success "✅ Security analysis completed successfully"
        return 0
    fi
}

# Execute main function
main "$@"
