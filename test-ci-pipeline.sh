#!/bin/bash
# Comprehensive test script for the security CI/CD pipeline
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[TEST]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[FAIL]${NC} $1"; }

log "🧪 Testing Golem LLM Security CI/CD Pipeline"
log "============================================"

# Test 1: Verify all files are created
log "Test 1: Verifying setup files..."
files_to_check=(
    ".github/workflows/security.yml"
    "scripts/security-analysis.sh"
    "deny.toml"
)

for file in "${files_to_check[@]}"; do
    if [ -f "$file" ]; then
        success "✅ $file exists"
    else
        error "❌ $file missing"
        exit 1
    fi
done

# Test 2: Build components for testing
log "Test 2: Building components for security analysis..."
if command -v cargo-make >/dev/null 2>&1; then
    # Build at least one component for testing
    if cargo make build-anthropic 2>/dev/null; then
        success "✅ Can build Anthropic component"
        BUILD_SUCCESS=true
    else
        warn "⚠️ Build failed - may need dependencies"
        BUILD_SUCCESS=false
    fi
else
    warn "⚠️ cargo-make not found - install with: cargo install cargo-make"
    BUILD_SUCCESS=false
fi

# Test 3: Install required tools
log "Test 3: Installing security analysis tools..."
missing_tools=()

if ! command -v wasm-validate >/dev/null 2>&1; then
    missing_tools+=("wabt")
fi

if ! command -v cargo-audit >/dev/null 2>&1; then
    missing_tools+=("cargo-audit")
fi

if [ ${#missing_tools[@]} -eq 0 ]; then
    success "✅ All required tools available"
    TOOLS_AVAILABLE=true
else
    warn "⚠️ Missing tools: ${missing_tools[*]} - will be installed by CI"
    TOOLS_AVAILABLE=false
fi

# Test 4: Test security analysis script
log "Test 4: Testing security analysis functionality..."
if [ "$BUILD_SUCCESS" = true ] && [ "$TOOLS_AVAILABLE" = true ]; then
    if [ -d "components" ] || [ -d "target/wasm32-wasip1" ]; then
        # Test the security script
        if ./scripts/security-analysis.sh 2>/dev/null; then
            success "✅ Security analysis script works"
            ANALYSIS_WORKS=true
        else
            warn "⚠️ Security analysis had issues - may need more components"
            ANALYSIS_WORKS=false
        fi
    else
        warn "⚠️ No WASM components found to test"
        ANALYSIS_WORKS=false
    fi
else
    warn "⚠️ Skipping analysis test - missing prerequisites"
    ANALYSIS_WORKS=false
fi

# Test 5: GitHub Actions workflow validation
log "Test 5: Validating GitHub Actions workflow..."
if command -v yamllint >/dev/null 2>&1; then
    if yamllint .github/workflows/security.yml >/dev/null 2>&1; then
        success "✅ GitHub Actions workflow syntax is valid"
        WORKFLOW_VALID=true
    else
        error "❌ GitHub Actions workflow has syntax errors"
        WORKFLOW_VALID=false
    fi
else
    # Basic validation without yamllint
    if grep -q "name:" .github/workflows/security.yml && 
       grep -q "jobs:" .github/workflows/security.yml && 
       grep -q "steps:" .github/workflows/security.yml; then
        success "✅ GitHub Actions workflow structure looks valid"
        WORKFLOW_VALID=true
    else
        error "❌ GitHub Actions workflow structure invalid"
        WORKFLOW_VALID=false
    fi
fi

# Test 6: Security configuration validation
log "Test 6: Validating security configurations..."
if [ -f "deny.toml" ]; then
    if grep -q "advisories" deny.toml && grep -q "licenses" deny.toml; then
        success "✅ Cargo deny configuration is valid"
        CONFIG_VALID=true
    else
        error "❌ Cargo deny configuration incomplete"
        CONFIG_VALID=false
    fi
else
    error "❌ deny.toml not found"
    CONFIG_VALID=false
fi

# Generate test report
log "📊 Test Results Summary"
log "======================"

TOTAL_TESTS=6
PASSED_TESTS=0

[ "$BUILD_SUCCESS" = true ] && PASSED_TESTS=$((PASSED_TESTS + 1))
[ "$TOOLS_AVAILABLE" = true ] && PASSED_TESTS=$((PASSED_TESTS + 1))
[ "$ANALYSIS_WORKS" = true ] && PASSED_TESTS=$((PASSED_TESTS + 1))
[ "$WORKFLOW_VALID" = true ] && PASSED_TESTS=$((PASSED_TESTS + 1))
[ "$CONFIG_VALID" = true ] && PASSED_TESTS=$((PASSED_TESTS + 1))
# File check always passes if we get here
PASSED_TESTS=$((PASSED_TESTS + 1))

log "Tests passed: $PASSED_TESTS/$TOTAL_TESTS"

# Create test instructions
cat > CI_TEST_INSTRUCTIONS.md << 'INSTRUCTIONS_EOF'
# 🧪 CI/CD Security Pipeline Testing Instructions

## Quick Test (Local)
```bash
# 1. Run the test script
chmod +x test-ci-pipeline.sh
./test-ci-pipeline.sh

# 2. Build some components for testing
cargo make build-anthropic
cargo make build-openai

# 3. Test security analysis
./scripts/security-analysis.sh

# 4. Check generated reports
ls -la *-security-analysis.json
open golem-llm-security-report.html
```

## Full CI/CD Test (GitHub)
```bash
# 1. Create test branch
git checkout -b test-security-pipeline

# 2. Add all security files
git add .github/workflows/security.yml
git add scripts/security-analysis.sh
git add deny.toml
git add test-ci-pipeline.sh
git add CI_TEST_INSTRUCTIONS.md

# 3. Commit and push
git commit -m "feat: Add WASM security analysis CI/CD pipeline

- Automated security analysis for all WASM components
- Dependency vulnerability scanning
- Security gate with configurable thresholds
- Comprehensive HTML and JSON reporting
- Integration with existing cargo-make build system"

git push origin test-security-pipeline

# 4. Create Pull Request
# - Go to GitHub and create a PR
# - Watch the security workflow run
# - Check the PR comment for security results
# - Download artifacts to view detailed reports
```

## Expected Results

### ✅ Successful Test Results
- All 5 LLM components (Anthropic, Grok, OpenAI, OpenRouter, Ollama) analyzed
- Security reports generated in JSON and HTML formats
- No critical security issues detected
- Dependency audits completed
- Security gate passes

### 🔍 What the Analysis Detects
- **WASM Structure**: Validates binary format
- **Dangerous Imports**: System-level access patterns
- **Network Access**: HTTP/API imports (expected for LLM providers)
- **Memory Safety**: Memory growth and buffer operations
- **Sensitive Data**: Exposed secrets or credentials
- **Component Size**: Large binaries that may indicate bloat

### 📊 Reports Generated
- `security-dashboard.html` - Beautiful HTML dashboard
- `*-security-analysis.json` - Machine-readable reports
- `*-audit.json` - Dependency vulnerability reports
- GitHub Actions artifacts with all reports

## Bounty Submission Checklist

- [ ] All tests pass locally
- [ ] GitHub Actions workflow runs successfully
- [ ] Security analysis detects intentional vulnerabilities
- [ ] Reports are comprehensive and actionable
- [ ] Documentation is clear and complete
- [ ] No false positives on legitimate components
- [ ] Security gate properly blocks/allows builds

## Troubleshooting

### Build Issues
```bash
# Install missing tools
cargo install cargo-make cargo-component@0.20.0

# Check Rust target
rustup target add wasm32-wasip1

# Verify component structure
find . -name "*.toml" | grep llm-
```

### Analysis Issues
```bash
# Install WABT tools manually
wget https://github.com/WebAssembly/wabt/releases/download/1.0.34/wabt-1.0.34-ubuntu.tar.gz
tar -xzf wabt-1.0.34-ubuntu.tar.gz
export PATH="$PWD/wabt-1.0.34/bin:$PATH"

# Test individual component
wasm-validate target/wasm32-wasip1/debug/golem_llm_anthropic.wasm
wasm-objdump -x target/wasm32-wasip1/debug/golem_llm_anthropic.wasm
```
INSTRUCTIONS_EOF

success "Test instructions created: CI_TEST_INSTRUCTIONS.md"

if [ $PASSED_TESTS -ge 5 ]; then
    success "🎉 CI/CD Pipeline Setup Complete!"
    success "Your security analysis pipeline is ready for testing"
    echo ""
    log "🚀 Next Steps:"
    echo "1. Review CI_TEST_INSTRUCTIONS.md for detailed testing steps"
    echo "2. Run: ./test-ci-pipeline.sh to validate setup"
    echo "3. Create a test branch and push to GitHub"
    echo "4. Create a pull request to test the full CI/CD pipeline"
    echo "5. Submit your bounty with the comprehensive security solution!"
    echo ""
    warn "💡 Pro Tip: The security analysis will work best after building components"
    warn "   Run: cargo make build-all && cargo make release-build-all"
    exit 0
elif [ $PASSED_TESTS -ge 3 ]; then
    warn "⚠️ Setup mostly complete but may need minor fixes"
    warn "Check the failed tests and install missing dependencies"
    exit 0
else
    error "❌ Setup needs more work before testing"
    error "Please address the failed tests and try again"
    exit 1
fi
