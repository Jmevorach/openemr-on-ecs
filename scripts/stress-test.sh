#!/usr/bin/env bash
# Synthesize representative CDK configurations without making AWS changes.

set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$PROJECT_ROOT"
CDK_COMMAND=${CDK_COMMAND:-"$PROJECT_ROOT/node_modules/.bin/cdk"}
if [[ -z "${PYTHON_COMMAND:-}" ]]; then
    if [[ -x "$PROJECT_ROOT/.venv/bin/python" ]]; then
        PYTHON_COMMAND="$PROJECT_ROOT/.venv/bin/python"
    else
        PYTHON_COMMAND=$(command -v python3 || true)
    fi
fi
printf -v CDK_APP_COMMAND '%q app.py' "$PYTHON_COMMAND"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configurations
# Note: certificate_arn is required for HTTPS (end-to-end encryption)
# This fixed placeholder is used only for local synthesis.
CERT_ARN="arn:aws:acm:us-west-2:123456789012:certificate/00000000-0000-0000-0000-000000000000"

# Using | as delimiter instead of : to avoid conflicts with ARN format
declare -a TEST_CONFIGS=(
    "minimal|certificate_arn=$CERT_ARN|enable_global_accelerator=false|enable_bedrock_integration=false|enable_data_api=false|create_serverless_analytics_environment=false|enable_monitoring_alarms=false"
    "minimal-with-monitoring|certificate_arn=$CERT_ARN|enable_global_accelerator=false|enable_bedrock_integration=false|enable_data_api=false|create_serverless_analytics_environment=false|enable_monitoring_alarms=true|monitoring_email=test@example.com"
    "standard|certificate_arn=$CERT_ARN|enable_global_accelerator=false|enable_bedrock_integration=true|enable_data_api=true|create_serverless_analytics_environment=false|enable_monitoring_alarms=false"
    "standard-with-monitoring|certificate_arn=$CERT_ARN|enable_global_accelerator=false|enable_bedrock_integration=true|enable_data_api=true|create_serverless_analytics_environment=false|enable_monitoring_alarms=true|monitoring_email=test@example.com"
    "full-featured|certificate_arn=$CERT_ARN|enable_global_accelerator=true|enable_bedrock_integration=true|enable_data_api=true|create_serverless_analytics_environment=true|enable_monitoring_alarms=false"
    "full-featured-with-monitoring|certificate_arn=$CERT_ARN|enable_global_accelerator=true|enable_bedrock_integration=true|enable_data_api=true|create_serverless_analytics_environment=true|enable_monitoring_alarms=true|monitoring_email=test@example.com"
)

PASSED=0
FAILED=0

log() {
    echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
    PASSED=$((PASSED + 1))
}

error() {
    echo -e "${RED}✗${NC} $1"
    FAILED=$((FAILED + 1))
}

test_config() {
    local config_name=$1
    local config_vars=$2

    log "Testing configuration: $config_name"
    log "Config vars: $config_vars"

    # Parse and apply configuration (using | as delimiter to avoid ARN conflicts)
    IFS='|' read -ra VARS <<< "$config_vars"
    local -a cdk_args=()

    for var in "${VARS[@]}"; do
        if [[ -n "$var" ]]; then
            # Split on first = only to preserve ARN format
            local key="${var%%=*}"
            local value="${var#*=}"

            if [[ -z "$key" || -z "$value" ]]; then
                error "Invalid configuration entry for $config_name"
                return 1
            fi
            cdk_args+=("-c" "$key=$value")
        fi
    done

    log "CDK args: ${cdk_args[*]}"

    # Test synthesis first
    log "Testing synthesis..."
    local log_file
    log_file=$(mktemp "${TMPDIR:-/tmp}/cdk-synth-${config_name}.XXXXXX.log")
    if "$CDK_COMMAND" synth --app "$CDK_APP_COMMAND" --no-lookups "${cdk_args[@]}" >"$log_file" 2>&1; then
        success "Synthesis successful for $config_name"
        rm -f "$log_file"
        return 0
    else
        error "Synthesis failed for $config_name"
        cat "$log_file"
        echo "Failure log retained at $log_file" >&2
        return 1
    fi
}

echo "========================================="
echo "CDK Configuration Synthesis Test"
echo "========================================="
echo ""
echo "This script tests CDK synthesis with representative configurations."
echo "It never deploys or destroys AWS resources."
echo ""

if [[ ! -x "$CDK_COMMAND" ]]; then
    echo "Pinned CDK CLI not found at $CDK_COMMAND; run npm ci." >&2
    exit 1
fi
if [[ ! -x "$PYTHON_COMMAND" ]]; then
    echo "Python not found; create .venv or provide an executable PYTHON_COMMAND." >&2
    exit 1
fi

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    source .venv/bin/activate 2>/dev/null || true
fi

# Run tests
for config in "${TEST_CONFIGS[@]}"; do
    IFS='|' read -ra PARTS <<< "$config"
    config_name="${PARTS[0]}"
    config_vars="${config#*|}"

    echo ""
    echo "----------------------------------------"
    echo "Test: $config_name"
    echo "----------------------------------------"

    test_config "$config_name" "$config_vars" || true

    echo ""
done

# Summary
echo "========================================="
echo "Test Summary"
echo "========================================="
echo -e "${GREEN}Passed:${NC} $PASSED"
echo -e "${RED}Failed:${NC} $FAILED"
echo ""

if [[ "$FAILED" -eq 0 ]]; then
    success "All tests passed!"
    exit 0
else
    error "Some tests failed"
    exit 1
fi
