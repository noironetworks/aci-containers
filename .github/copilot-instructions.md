# ACI Containers CNI Plugin - AI Development Guide

## Project Overview

This is the Cisco ACI CNI plugin that integrates Kubernetes with ACI networking using the OpFlex protocol and Open vSwitch. The project has three main components that work together to provide L2/L3 networking, IP management, and policy enforcement for Kubernetes clusters.

## Core Architecture

### Key Components
- **Controller** (`cmd/controller`, `pkg/controller`): Watches Kubernetes resources and programs ACI fabric via APIC REST API
- **Host Agent** (`cmd/hostagent`, `pkg/hostagent`): Node-level daemon that manages OpFlex configuration and Open vSwitch
- **GBP Server** (`cmd/gbpserver`, `pkg/gbpserver`): Group-based policy server for network policy management

### Data Flow
1. Controller monitors K8s API and translates resources to ACI policy
2. Controller communicates with APIC controllers via REST API
3. Host Agent receives configuration updates and configures OpFlex agent
4. OpFlex agent programs Open vSwitch flows on each node

## Development Workflows

### Building and Testing
```bash
# Run all component tests
make check

# Individual component testing
make check-controller
make check-hostagent  
make check-gbpserver

# Build static binaries
make all-static

# Build specific component
make dist/aci-containers-controller
```

### Key Build Patterns
- Static builds use `CGO_ENABLED=0` and inject version info via `-ldflags`
- Multi-component testing with individual coverage profiles
- Docker builds in `docker/` directory with component-specific Dockerfiles
- Cross-compilation using `GOBUILD` container environment

## Project Conventions

### Configuration Management
- Components use JSON config files loaded via `-config-path` flags
- Environment variables override config (e.g., `APIC_USERNAME`, `APIC_PASSWORD`)
- OpFlex config written to filesystem directories for agent consumption
- Config structs in `pkg/*/config.go` with `InitFlags()` patterns

### Custom Resource Patterns
- CRDs follow `aci.*` group naming (e.g., `aci.snat`, `aci.erspan`)
- Types in `pkg/*/apis/*/v1/types.go` with kubebuilder annotations
- Generated clientsets and deep copy functions
- Status subresources with state machines (Ready/Failed/IpPortsExhausted)

### APIC Integration
- APIC connection handling in `pkg/apicapi` with retry logic
- Version-dependent feature detection (e.g., SnatPbrFltrChain for v4.2+)
- OpFlex device management with fabric path tracking
- Objects use Distinguished Names (DN) for ACI hierarchy

### Testing Patterns
- Extensive use of fake clients and controller sources
- Component isolation with mock APIC responses
- Test fixtures in `*_test.go` files with helper functions
- Coverage exclusion via `exclude-covprof.conf`

## Critical Files for Understanding

- `pkg/controller/controller.go`: Main controller logic and APIC connection
- `pkg/hostagent/agent.go`: Host agent initialization and pod management
- `pkg/gbpserver/server.go`: GBP server startup and gRPC handling
- `pkg/apicapi/`: APIC REST API abstraction layer
- `Makefile`: Build targets and component dependencies
- `.travis.yml`: CI configuration and test matrix
- `docker/travis/Dockerfile.*`: Dockerfiles for CI builds
- `docker/travis/*.sh`: CI build scripts

## Common Gotchas

- OpFlex configuration is file-based; ensure directory permissions are correct
- APIC version detection affects available features - check version conditionals
- Component configs have many interdependent fields - use examples from tests
- CRD registration timing matters - use proper controller initialization order
- Network policy translation involves complex ACI contract generation

## Debugging Tips

- Enable debug logging with `--log-level=debug`
- Check OpFlex agent logs for connectivity issues
- Use `gbpserver --inspect` for policy state examination
- APIC GUI shows translated policies for verification
- Test components individually before integration testing

## Test Coverage Analysis

### Current Coverage Status
- **Controller**: 54.2% coverage (18,721 lines) - Primary improvement target
- **Host Agent**: 62.4% coverage - Good baseline, moderate improvement potential  
- **GBP Server**: 54.1% coverage - Moderate baseline, good improvement potential
- **Target**: 75% overall coverage across all components

### Coverage Improvement Strategy
1. **Controller Priority** (Highest Impact): Need ~3,900 additional lines covered
   - Focus on 0% coverage functions first for maximum impact
   - Target networking, APIC integration, and initialization functions
   - AaepMonitor, service utilities, network policy functions are high-value

2. **Component Analysis Tools**:
   ```bash
   # Generate coverage reports
   go test -coverprofile=coverage.out ./pkg/controller
   go tool cover -html=coverage.out  # Visual analysis
   go tool cover -func=coverage.out | grep "0.0%"  # Find untested functions
   ```

3. **Function Signature Verification**:
   ```bash
   # Before writing tests, verify actual function signatures
   grep -n "func.*queueIPNetPolUpdates" pkg/controller/*.go
   grep -n "func.*queueEndpointsNetPolUpdates" pkg/controller/*.go
   ```

## Unit Testing Best Practices

### Test File Organization
- Create `*_test.go` files alongside source files
- Use descriptive test file names: `aaepmonitor_test.go`, `network_test.go`
- Group related function tests in single files for better organization

### ACI-Specific Test Patterns

#### 1. Controller Testing Pattern
```go
func TestFunctionName(t *testing.T) {
    // Use testController() helper for consistent setup
    cont := testController()
    
    // Mock Kubernetes resources
    namespace := &v1.Namespace{
        ObjectMeta: metav1.ObjectMeta{Name: "testns"},
    }
    cont.fakeNamespaceSource.Add(namespace)
    
    // Test the function
    result := cont.functionUnderTest(params)
    
    // Validate results
    assert.Equal(t, expected, result)
}
```

#### 2. APIC Integration Testing
```go
func TestApicObjectCreation(t *testing.T) {
    // Test APIC object creation without real APIC connection
    obj := apicExtNetworkContainer("test-net", "192.168.1.0/24")
    
    // Validate APIC object structure
    assert.Equal(t, "test-net", obj.GetName())
    assert.Contains(t, obj.GetDn(), "test-net")
}
```

#### 3. Network Function Testing
```go
func TestNetworkPolicyFunctions(t *testing.T) {
    cont := testController()
    
    // Create test data with correct types
    ipMap := map[string]bool{"192.168.1.1": true}
    endpoints := &v1.Endpoints{...}  // Use proper Kubernetes types
    portMap := map[string]targetPort{
        "http": {proto: v1.ProtocolTCP, ports: []int{80, 8080}},
    }
    
    // Test network policy queue functions
    cont.queueIPNetPolUpdates(ipMap)
    cont.queueEndpointsNetPolUpdates(endpoints)
    cont.queuePortNetPolUpdates(portMap)
}
```

### Common Testing Pitfalls to Avoid

1. **Function Signature Mismatches**: Always verify function signatures before writing tests
   - Use `grep` to find actual function definitions
   - Check parameter types carefully (e.g., `map[string]bool` vs `net.IP`)

2. **Kubernetes API Usage**: Use proper Kubernetes types
   - Import correct packages: `v1 "k8s.io/api/core/v1"`
   - Use `metav1.ObjectMeta` for object metadata
   - Verify struct field names (e.g., `proto v1.Protocol`, not `protocol`)

3. **Mock Setup**: Ensure proper test environment
   - Use `testController()` for consistent controller setup
   - Add resources to fake sources before testing
   - Clean up test state between tests

### Test Coverage Validation
```bash
# Run tests with coverage
go test -coverprofile=coverage.out ./pkg/controller

# Check improvement
go tool cover -func=coverage.out | tail -1

# Identify remaining gaps
go tool cover -func=coverage.out | grep "0.0%" | head -20
```

### Successful Test Examples
Reference these implemented test files for patterns:
- `pkg/controller/aaepmonitor_test.go` - CRD functionality testing
- `pkg/controller/network_test.go` - Network function testing with corrected signatures
- `pkg/controller/service_util_test.go` - APIC integration testing
- `pkg/controller/controller_basic_test.go` - Core controller function testing

## Contribution Guidelines
- Follow existing code patterns and conventions
- Write unit tests for new features and bug fixes
- Target 0% coverage functions for maximum coverage impact
- Verify function signatures before writing tests
- Use `testController()` pattern for consistency
- Ensure code passes `make check` before submitting PRs
 

