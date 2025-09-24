#!/bin/bash

# Comprehensive coverage script for ACI Containers
# Uses Docker for Linux-specific components and native testing for others

set -e

echo "🚀 Starting comprehensive coverage analysis for ACI Containers"
echo

# Create coverage output directory
mkdir -p coverage-results

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to extract coverage percentage from go tool cover output
extract_coverage() {
    local coverage_file="$1"
    if [ -f "$coverage_file" ]; then
        go tool cover -func="$coverage_file" | tail -1 | awk '{print $NF}' | sed 's/%//'
    else
        echo "0.0"
    fi
}

print_status "Testing components locally (macOS compatible)..."

# 1. Test Controller (works locally)
print_status "Running Controller coverage tests..."
if go test -coverprofile=coverage-results/controller.out ./pkg/controller 2>/dev/null; then
    CONTROLLER_COV=$(extract_coverage "coverage-results/controller.out")
    print_status "Controller coverage: ${CONTROLLER_COV}%"
else
    print_warning "Controller tests failed, using existing results if available"
    if [ -f "controller_coverage.out" ]; then
        cp controller_coverage.out coverage-results/controller.out
        CONTROLLER_COV=$(extract_coverage "coverage-results/controller.out")
        print_status "Controller coverage (cached): ${CONTROLLER_COV}%"
    else
        CONTROLLER_COV="0.0"
    fi
fi

# 2. Test APICAPI (works locally)
print_status "Running APICAPI coverage tests..."
if go test -coverprofile=coverage-results/apicapi.out ./pkg/apicapi 2>/dev/null; then
    APICAPI_COV=$(extract_coverage "coverage-results/apicapi.out")
    print_status "APICAPI coverage: ${APICAPI_COV}%"
else
    print_warning "APICAPI tests failed"
    APICAPI_COV="0.0"
fi

# 3. Test other small components locally
print_status "Running other component tests..."

# Test index
if go test -coverprofile=coverage-results/index.out ./pkg/index 2>/dev/null; then
    INDEX_COV=$(extract_coverage "coverage-results/index.out")
    print_status "Index coverage: ${INDEX_COV}%"
else
    INDEX_COV="0.0"
    print_warning "Index tests not available"
fi

print_status "Using Podman for Linux-specific components..."

# 4. Test Hostagent using Podman (needs Linux environment)
print_status "Building Podman image for Hostagent coverage..."
if podman build -f Dockerfile.coverage -t aci-coverage . >/dev/null 2>&1; then
    print_status "Running Hostagent coverage in Podman..."
    if podman run --rm -v "$(pwd)/coverage-results:/workspace/coverage-results" aci-coverage sh -c "make check-hostagent && cp covprof-hostagent coverage-results/hostagent.out" 2>/dev/null; then
        HOSTAGENT_COV=$(extract_coverage "coverage-results/hostagent.out")
        print_status "Hostagent coverage: ${HOSTAGENT_COV}%"
    else
        print_error "Hostagent Podman tests failed"
        HOSTAGENT_COV="0.0"
    fi
else
    print_error "Failed to build Podman image for coverage"
    HOSTAGENT_COV="0.0"
fi

# 5. Test GBPServer using Podman
print_status "Building Podman image for GBPServer coverage..."
if podman build -f Dockerfile.gbpserver -t aci-gbpserver . >/dev/null 2>&1; then
    print_status "Running GBPServer coverage in Podman..."
    if podman run --rm -v "$(pwd)/coverage-results:/workspace/coverage-results" aci-gbpserver sh -c "make check-gbpserver && cp covprof-gbpserver coverage-results/gbpserver.out" 2>/dev/null; then
        GBPSERVER_COV=$(extract_coverage "coverage-results/gbpserver.out")
        print_status "GBPServer coverage: ${GBPSERVER_COV}%"
    else
        print_error "GBPServer Podman tests failed"
        GBPSERVER_COV="0.0"
    fi
else
    print_error "Failed to build Podman image for GBPServer"
    GBPSERVER_COV="0.0"
fi

# Summary
echo
echo "📊 COVERAGE SUMMARY"
echo "===================="
printf "%-15s %8s %10s\n" "Component" "Coverage" "Status"
echo "------------------------------------"

# Function to print coverage line with status
print_coverage_line() {
    local component="$1"
    local coverage="$2"
    local status_color=""
    local status_text=""
    
    if (( $(echo "$coverage >= 75.0" | bc -l) )); then
        status_color="${GREEN}"
        status_text="✅ Target"
    elif (( $(echo "$coverage >= 50.0" | bc -l) )); then
        status_color="${YELLOW}"
        status_text="⚠️ Partial"
    else
        status_color="${RED}"
        status_text="❌ Low"
    fi
    
    printf "%-15s %7.1f%% ${status_color}%10s${NC}\n" "$component" "$coverage" "$status_text"
}

print_coverage_line "Controller" "$CONTROLLER_COV"
print_coverage_line "APICAPI" "$APICAPI_COV"
print_coverage_line "Index" "$INDEX_COV"
print_coverage_line "Hostagent" "$HOSTAGENT_COV"
print_coverage_line "GBPServer" "$GBPSERVER_COV"

echo
echo "📁 Coverage files saved to coverage-results/ directory"
echo

# Calculate overall progress
if command -v bc >/dev/null 2>&1; then
    TOTAL_COVERED_COMPONENTS=0
    if (( $(echo "$CONTROLLER_COV >= 75.0" | bc -l) )); then
        ((TOTAL_COVERED_COMPONENTS++))
    fi
    if (( $(echo "$APICAPI_COV >= 75.0" | bc -l) )); then
        ((TOTAL_COVERED_COMPONENTS++))
    fi
    if (( $(echo "$INDEX_COV >= 75.0" | bc -l) )); then
        ((TOTAL_COVERED_COMPONENTS++))
    fi
    if (( $(echo "$HOSTAGENT_COV >= 75.0" | bc -l) )); then
        ((TOTAL_COVERED_COMPONENTS++))
    fi
    if (( $(echo "$GBPSERVER_COV >= 75.0" | bc -l) )); then
        ((TOTAL_COVERED_COMPONENTS++))
    fi
    
    echo "🎯 Components meeting 75% target: $TOTAL_COVERED_COMPONENTS/5"
    
    if [ "$TOTAL_COVERED_COMPONENTS" -ge 4 ]; then
        print_status "🏆 Great progress! Almost there!"
    elif [ "$TOTAL_COVERED_COMPONENTS" -ge 2 ]; then
        print_status "📈 Good progress! Keep going!"
    else
        print_status "🔧 Work needed to reach coverage targets"
    fi
fi

echo
print_status "Coverage analysis complete!"