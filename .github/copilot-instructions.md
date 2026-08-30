
# ACI Containers CNI Plugin — AI Agent Guide

## Essential Architecture

**Components:**
- `cmd/controller`, `pkg/controller`: Controller — watches K8s resources, programs ACI via APIC REST API
- `cmd/hostagent`, `pkg/hostagent`: Host Agent — configures OpFlex and Open vSwitch per node
- `cmd/gbpserver`, `pkg/gbpserver`: GBP Server — manages network policy (Group-Based Policy)

**Data Flow:**
1. Controller: K8s API → ACI policy (APIC REST)
2. Host Agent: Receives config, updates OpFlex agent
3. OpFlex agent: Programs Open vSwitch flows

## Developer Workflow

**Build/Test:**
- Run all tests: `make check`
- Component tests: `make check-controller`, `make check-hostagent`, `make check-gbpserver`
- Static builds: `make all-static` (uses `CGO_ENABLED=0`)
- Build binaries: `make dist/aci-containers-controller`
- Docker builds: see `docker/` for component Dockerfiles

**Testing:**
- Test assets (kubectl, kube-apiserver, etcd) auto-downloaded
- Coverage: `go test -coverprofile=coverage.out ./pkg/controller`
- Exclude coverage: `exclude-covprof.conf`

## Complete Testing Guide

### Running Tests Successfully

**Recommended Approach:**
```bash
# Complete test suite (takes ~5 minutes)
make goinstall && make check > /tmp/check.log 2>&1 && echo "SUCCESS" || echo "FAILED"

# Check results
cat /tmp/check.log
```

**Component Coverage Results:**
- **IPAM**: 95.4% coverage (excellent)
- **Index**: 85.9% coverage (good) 
- **APICAPI**: 75.1% coverage (good)
- **Controller**: 53.8% coverage (needs improvement - 305 uncovered functions)
- **HostAgent**: 47.3% coverage (needs improvement)
- **GBP Server**: 55.2% coverage (moderate)

**Individual Component Tests:**
```bash
# Fast components (< 1 second each)
make check-ipam     # 95.4% coverage
make check-index    # 85.9% coverage  
make check-apicapi  # 75.1% coverage

# Host agent (requires envtest setup)
make check-hostagent  # 47.3% coverage, needs KUBEBUILDER_ASSETS

# Controller (takes 4.5 minutes!)
make check-controller # 53.8% coverage, ~272 seconds execution time

# Other components
make check-gbpserver
make check-webhook
make check-certmanager
make check-acicontainersoperator
```

**Important Notes:**
- Controller tests take **4.5 minutes** to complete - don't assume they've hung
- HostAgent tests require `test-tools` target (runs `tools/setup-envtest.bash`)
- Redirect output to log file to avoid terminal hangs: `make check > /tmp/check.log 2>&1`
- Tests pass successfully when environment is properly configured

**Environment Requirements:**
- Go 1.25+ (matches Travis CI)
- Proper GOPATH/GOROOT configuration
- Network access for module downloads (set GOPROXY if needed)
- Ubuntu/Linux environment (matches CI)

**Container Notes:**
- ARM64/amd64 builds: Go binary must match container arch
- Linux environment resolves network/CGO dependencies

## Project Conventions

- Config: JSON files via `-config-path`, env vars override (e.g. `APIC_USERNAME`)
- OpFlex config: written to filesystem for agent
- CRDs: `aci.*` group, types in `pkg/*/apis/*/v1/types.go` (kubebuilder annotations)
- APIC integration: `pkg/apicapi` (retry logic, DN hierarchy)
- Status subresources: Ready/Failed/IpPortsExhausted

## Key Files/Directories

- `pkg/controller/controller.go`: Controller logic, APIC connection
- `pkg/hostagent/agent.go`: Host agent, pod management
- `pkg/gbpserver/server.go`: GBP server, gRPC
- `pkg/apicapi/`: APIC REST abstraction
- `Makefile`: Build/test targets
- `docker/`: Dockerfiles/scripts

## Patterns & Gotchas

- OpFlex config is file-based — check directory permissions
- APIC version detection gates features (see version conditionals)
- CRD registration order matters for controller startup
- Network policy translation: complex ACI contract generation
- Use test helpers (`testController()`) for consistent test setup

## Testing & Coverage

- Use fake clients, mock APIC responses, fixtures in `*_test.go`
- Coverage: focus on 0% coverage functions first (see `go tool cover -func=coverage.out | grep "0.0%"`)
- Example test files: `pkg/controller/aaepmonitor_test.go`, `pkg/controller/network_test.go`, `pkg/hostagent/agent_coverage_test.go`
- Host Agent coverage improved by targeting utility functions, initializing maps/slices to avoid nil pointers

**Test Patterns:**
```go
func TestFunctionName(t *testing.T) {
    cont := testController()
    ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "testns"}}
    cont.fakeNamespaceSource.Add(ns)
    result := cont.functionUnderTest(params)
    assert.Equal(t, expected, result)
}
```

## Debugging

- Enable debug logging: `--log-level=debug`
- Check OpFlex agent logs for connectivity
- Use `gbpserver --inspect` for policy state
- APIC GUI: verify translated policies

## Test Coverage Analysis

### Current Coverage Status
- **Controller**: 54.1% coverage (18,721 lines) - Primary improvement target
- **Host Agent**: 48.9% coverage - Successfully improved from 47.9% through systematic 0% function testing
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

## Contribution

- Follow code patterns/conventions
- Write unit tests for new features/bugfixes
- Target 0% coverage functions for maximum coverage impact
- Verify function signatures before writing tests
- Use `testController()` pattern for consistency
- **ALWAYS run `go fmt ./...` or `make check-gofmt` before committing** to ensure consistent code formatting
- Ensure code passes `make check` before submitting PRs

#### Troubleshooting
- If authentication issues occur with container registries, try alternative base images
- For build failures, ensure Go version matches the container architecture
- Test failures due to nil pointer dereferences indicate missing Kubernetes client setup in tests

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
- **Controller**: 54.1% coverage (18,721 lines) - Primary improvement target
- **Host Agent**: 48.9% coverage - Successfully improved from 47.9% through systematic 0% function testing
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
- `pkg/hostagent/agent_coverage_test.go` - **PROVEN COVERAGE IMPROVEMENT PATTERN** - Improved hostagent from 47.9% to 48.9%

### Host Agent Testing Success Pattern

#### Proven Strategy for Coverage Improvement
The hostagent component was successfully improved from 47.9% to 48.9% coverage by systematically targeting 0% coverage functions with utility-focused unit tests. This approach provides the highest impact per test function written.

#### Host Agent Test Implementation Pattern
```go
// pkg/hostagent/agent_coverage_test.go - Follow this proven pattern
func TestUtilityFunctionGroup(t *testing.T) {
    // Target utility functions that don't require complex setup
    result := functionUnderTest(testInput)
    assert.Equal(t, expected, result)
}

func TestSnatPolicyFunctions(t *testing.T) {
    // Initialize policy maps properly to avoid nil pointer issues
    agent := &HostAgent{
        snatPolicyMap: make(map[string]*snatPolicy),
    }
    
    // Test policy utility functions
    label := agent.generatePolicyLabel(testData)
    assert.NotEmpty(t, label)
}
```

#### Key Learnings from Host Agent Testing
1. **Target 0% Coverage Functions First**: Maximum impact with minimal effort
2. **Focus on Utility Functions**: Avoid complex dependency chains
3. **Initialize Maps and Slices**: Prevent nil pointer dereferences in tests
4. **Use Stub Functions**: Test environment-specific functions with simple stubs
5. **Test Scheduling Logic**: Verify queue management and event handling


#### Host Agent Coverage Improvement Areas Validated
- **SNAT Policy Functions**: Policy label generation, matching, and validation
- **Scheduling Functions**: Queue management and delayed execution
- **Environment Stubs**: Network interface and system-specific functionality
- **Fabric Discovery**: ACI fabric path and attachment point discovery
- **Utility Functions**: String manipulation, validation, and helper functions

#### Test Environment Best Practices
- **Local Testing**: Faster feedback, simpler debugging, proven successful for hostagent
- **Containerized Testing**: Required for Linux-specific CNI functionality, use for final validation
- **Coverage Analysis**: Use `go tool cover -func=coverage.out | grep "0.0%"` to identify high-impact targets
- **Incremental Approach**: Add 5-10 test functions per iteration, validate coverage improvement

## Contribution Guidelines
- Follow existing code patterns and conventions
- Write unit tests for new features and bug fixes
- Target 0% coverage functions for maximum coverage impact
- Verify function signatures before writing tests
- Use `testController()` pattern for consistency
- **ALWAYS run `go fmt ./...` or `make check-gofmt` before committing** to ensure consistent code formatting
- Ensure code passes `make check` before submitting PRs
 
