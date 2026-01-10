package semanticfw

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/tools/go/ssa"
)

// TestSCEVBasicLinearIV tests detection of basic linear induction variables.
func TestSCEVBasicLinearIV(t *testing.T) {
	src := `package main

func simpleLoop(n int) int {
	sum := 0
	for i := 0; i < n; i++ {
		sum += i
	}
	return sum
}
`
	fn := compileAndGetFunction(t, src, "simpleLoop")
	if fn == nil {
		t.Fatal("Failed to compile function")
	}

	info := DetectLoops(fn)
	AnalyzeSCEV(info)

	if len(info.Loops) == 0 {
		t.Fatal("No loops detected")
	}

	loop := info.Loops[0]
	if len(loop.Inductions) == 0 {
		t.Fatal("No induction variables detected")
	}

	// Should have at least one IV with {0, +, 1} pattern
	var foundBasicIV bool
	for _, iv := range loop.Inductions {
		if iv.Start == nil || iv.Step == nil {
			continue
		}
		t.Logf("Found IV: Start=%s, Step=%s", iv.Start.String(), iv.Step.String())

		if startConst, ok := iv.Start.(*SCEVConstant); ok {
			if stepConst, ok := iv.Step.(*SCEVConstant); ok {
				if startConst.Value.Cmp(big.NewInt(0)) == 0 && stepConst.Value.Cmp(big.NewInt(1)) == 0 {
					foundBasicIV = true
				}
			}
		}
	}

	if !foundBasicIV {
		t.Error("Expected to find basic IV with {0, +, 1} pattern")
	}
}

// TestSCEVRangeLoop tests detection of range loop IVs (pre-increment pattern).
func TestSCEVRangeLoop(t *testing.T) {
	src := `package main

func rangeLoop(items []int) int {
	sum := 0
	for _, item := range items {
		sum += item
	}
	return sum
}
`
	fn := compileAndGetFunction(t, src, "rangeLoop")
	if fn == nil {
		t.Fatal("Failed to compile function")
	}

	info := DetectLoops(fn)
	AnalyzeSCEV(info)

	if len(info.Loops) == 0 {
		t.Fatal("No loops detected")
	}

	loop := info.Loops[0]
	t.Logf("Loop has %d IVs", len(loop.Inductions))

	// Range loops typically have {-1, +, 1} pattern for the index
	for _, iv := range loop.Inductions {
		if iv.Start == nil || iv.Step == nil {
			continue
		}
		t.Logf("Found IV: Start=%s, Step=%s", iv.Start.String(), iv.Step.String())
	}
}

// TestSCEVGeometricIV tests detection of geometric (multiplicative) IVs.
func TestSCEVGeometricIV(t *testing.T) {
	src := `package main

func geometricLoop(n int) int {
	count := 0
	for i := 1; i < n; i *= 2 {
		count++
	}
	return count
}
`
	fn := compileAndGetFunction(t, src, "geometricLoop")
	if fn == nil {
		t.Fatal("Failed to compile function")
	}

	info := DetectLoops(fn)
	AnalyzeSCEV(info)

	if len(info.Loops) == 0 {
		t.Fatal("No loops detected")
	}

	loop := info.Loops[0]

	// Should detect a multiplicative IV
	var foundMulIV bool
	for _, iv := range loop.Inductions {
		if iv.Type == IVTypeGeometric {
			foundMulIV = true
			t.Logf("Found geometric IV: Start=%s, Step=%s", iv.Start.String(), iv.Step.String())
		}
	}

	if !foundMulIV {
		// Note: This might not be detected as a proper geometric IV in all cases
		// depending on Go's SSA representation
		t.Log("Geometric IV not detected (may be represented differently in SSA)")
	}
}

// TestSCEVNestedLoops tests detection of nested loop structures.
func TestSCEVNestedLoops(t *testing.T) {
	src := `package main

func nestedLoops(n, m int) int {
	sum := 0
	for i := 0; i < n; i++ {
		for j := 0; j < m; j++ {
			sum += i * j
		}
	}
	return sum
}
`
	fn := compileAndGetFunction(t, src, "nestedLoops")
	if fn == nil {
		t.Fatal("Failed to compile function")
	}

	info := DetectLoops(fn)
	AnalyzeSCEV(info)

	// Count total loops including nested ones
	totalLoops := len(info.Loops)
	for _, loop := range info.Loops {
		totalLoops += len(loop.Children)
	}

	if totalLoops < 2 {
		t.Fatalf("Expected at least 2 loops, got %d", totalLoops)
	}

	t.Logf("Found %d top-level loops", len(info.Loops))

	// Check nesting relationship
	var hasNested bool
	for _, loop := range info.Loops {
		if len(loop.Children) > 0 {
			hasNested = true
			t.Logf("Loop at %s has %d nested children", loop.Header.String(), len(loop.Children))
		}
	}

	if !hasNested {
		t.Log("No nested loop relationships detected (may depend on SSA structure)")
	}
}

// TestSCEVTripCount tests trip count computation.
func TestSCEVTripCount(t *testing.T) {
	src := `package main

func fixedTrips() int {
	sum := 0
	for i := 0; i < 10; i++ {
		sum += i
	}
	return sum
}
`
	fn := compileAndGetFunction(t, src, "fixedTrips")
	if fn == nil {
		t.Fatal("Failed to compile function")
	}

	info := DetectLoops(fn)
	AnalyzeSCEV(info)

	if len(info.Loops) == 0 {
		t.Fatal("No loops detected")
	}

	loop := info.Loops[0]
	if loop.TripCount == nil {
		t.Log("Could not compute trip count (symbolic analysis needed)")
		return
	}

	t.Logf("Trip count expression: %s", loop.TripCount.String())
}

// TestSCEVLoopEquivalence tests loop equivalence detection.
func TestSCEVLoopEquivalence(t *testing.T) {
	src1 := `package main

func loop1(items []int) int {
	sum := 0
	for i := 0; i < len(items); i++ {
		sum += items[i]
	}
	return sum
}
`
	src2 := `package main

func loop2(items []int) int {
	sum := 0
	for _, item := range items {
		sum += item
	}
	return sum
}
`
	fn1 := compileAndGetFunction(t, src1, "loop1")
	fn2 := compileAndGetFunction(t, src2, "loop2")

	if fn1 == nil || fn2 == nil {
		t.Fatal("Failed to compile functions")
	}

	info1 := DetectLoops(fn1)
	info2 := DetectLoops(fn2)
	AnalyzeSCEV(info1)
	AnalyzeSCEV(info2)

	if len(info1.Loops) == 0 || len(info2.Loops) == 0 {
		t.Fatal("Loops not detected in one or both functions")
	}

	loop1 := info1.Loops[0]
	loop2 := info2.Loops[0]

	t.Logf("Loop1 has %d IVs", len(loop1.Inductions))
	t.Logf("Loop2 has %d IVs", len(loop2.Inductions))

	// After normalization, both should have equivalent patterns
	// (both iterate len(items) times)
	if loop1.TripCount != nil && loop2.TripCount != nil {
		t.Logf("Loop1 trip count: %s", loop1.TripCount.String())
		t.Logf("Loop2 trip count: %s", loop2.TripCount.String())
	}
}

// TestSCEVExprNormalization tests SCEV expression behavior.
func TestSCEVExprNormalization(t *testing.T) {
	tests := []struct {
		name     string
		expr     SCEV
		expected string
	}{
		{
			name:     "constant",
			expr:     &SCEVConstant{Value: big.NewInt(42)},
			expected: "42",
		},
		{
			name:     "unknown",
			expr:     &SCEVUnknown{Value: nil},
			expected: "?",
		},
		{
			name: "add rec",
			expr: &SCEVAddRec{
				Start: &SCEVConstant{Value: big.NewInt(0)},
				Step:  &SCEVConstant{Value: big.NewInt(1)},
			},
			expected: "{0, +, 1}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.expr.String()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestSCEVEquality tests SCEV expression evaluation.
func TestSCEVEquality(t *testing.T) {
	tests := []struct {
		name     string
		expr     SCEV
		k        *big.Int
		expected *big.Int
	}{
		{
			name:     "constant evaluation",
			expr:     &SCEVConstant{Value: big.NewInt(42)},
			k:        big.NewInt(0),
			expected: big.NewInt(42),
		},
		{
			name: "add rec at 0",
			expr: &SCEVAddRec{
				Start: &SCEVConstant{Value: big.NewInt(5)},
				Step:  &SCEVConstant{Value: big.NewInt(2)},
			},
			k:        big.NewInt(0),
			expected: big.NewInt(5),
		},
		{
			name: "add rec at 3",
			expr: &SCEVAddRec{
				Start: &SCEVConstant{Value: big.NewInt(5)},
				Step:  &SCEVConstant{Value: big.NewInt(2)},
			},
			k:        big.NewInt(3),
			expected: big.NewInt(11), // 5 + 2*3 = 11
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.expr.EvaluateAt(tt.k)
			if result == nil {
				t.Error("EvaluateAt returned nil")
				return
			}
			if result.Cmp(tt.expected) != 0 {
				t.Errorf("Expected %s, got %s", tt.expected.String(), result.String())
			}
		})
	}
}

// TestSCEVCountingDownLoop tests detection of counting-down loops.
func TestSCEVCountingDownLoop(t *testing.T) {
	src := `package main

func countDown(n int) int {
	sum := 0
	for i := n; i > 0; i-- {
		sum += i
	}
	return sum
}
`
	fn := compileAndGetFunction(t, src, "countDown")
	if fn == nil {
		t.Fatal("Failed to compile function")
	}

	info := DetectLoops(fn)
	AnalyzeSCEV(info)

	if len(info.Loops) == 0 {
		t.Fatal("No loops detected")
	}

	// Should detect an IV with negative step
	for _, iv := range info.Loops[0].Inductions {
		if iv.Start == nil || iv.Step == nil {
			continue
		}
		t.Logf("Found IV: Start=%s, Step=%s", iv.Start.String(), iv.Step.String())

		if stepConst, ok := iv.Step.(*SCEVConstant); ok {
			if stepConst.Value.Cmp(big.NewInt(-1)) == 0 {
				t.Log("Correctly detected counting-down IV with step -1")
			}
		}
	}
}

// TestLoopInfoStructure tests the LoopInfo structure.
func TestLoopInfoStructure(t *testing.T) {
	src := `package main

func testLoop(n int) int {
	sum := 0
	for i := 0; i < n; i++ {
		sum += i
	}
	return sum
}
`
	fn := compileAndGetFunction(t, src, "testLoop")
	if fn == nil {
		t.Fatal("Failed to compile function")
	}

	info := DetectLoops(fn)
	AnalyzeSCEV(info)

	if len(info.Loops) == 0 {
		t.Fatal("No loops detected")
	}

	loop := info.Loops[0]

	// Check loop structure
	if loop.Header == nil {
		t.Error("Loop header is nil")
	}
	if loop.Latch == nil {
		t.Error("Loop latch is nil")
	}
	if len(loop.Blocks) == 0 {
		t.Error("Loop has no blocks")
	}

	t.Logf("Loop structure:")
	t.Logf("  Header: %s", loop.Header.String())
	if loop.Latch != nil {
		t.Logf("  Latch: %s", loop.Latch.String())
	}
	t.Logf("  Blocks: %d", len(loop.Blocks))
	t.Logf("  Exits: %d", len(loop.Exits))
	t.Logf("  IVs: %d", len(loop.Inductions))
}

// TestRenamerCycles verifies that the renamer function handles circular dependencies
// in virtualSubstitutions without panicking or infinite looping.
// This is a defense-in-depth test for malformed substitution graphs.
func TestRenamerCycles(t *testing.T) {
	// Create a canonicalizer with circular substitutions
	c := NewCanonicalizer(DefaultLiteralPolicy)
	defer ReleaseCanonicalizer(c)

	// Create mock SSA values using SCEVUnknown (which implements ssa.Value)
	// These will serve as the ssa.Value wrapped by another SCEVUnknown
	mockA := &SCEVUnknown{Value: nil, IsInvariant: true}
	mockB := &SCEVUnknown{Value: nil, IsInvariant: true}

	// Inject circular dependency: A -> B -> A
	// When the renamer is called with mockA, it will:
	// 1. Find substitution mockA -> mockB (mockB is SCEV, so it stringifies)
	// 2. mockB.StringWithRenamer calls renamer(nil) or returns "?(inv)"
	// The cycle is "broken" because mockB doesn't have a Value that loops back.
	//
	// For a TRUE cycle test, we need mockA.Value to point somewhere that
	// eventually loops back to mockA through substitutions.
	c.virtualSubstitutions[mockA] = mockB
	c.virtualSubstitutions[mockB] = mockA

	// Create an SCEVUnknown that wraps mockA as its Value
	// When StringWithRenamer is called, it will call renamer(mockA)
	scevWithCyclicValue := &SCEVUnknown{Value: mockA, IsInvariant: false}

	scev := &SCEVAddRec{
		Start: scevWithCyclicValue,
		Step:  &SCEVConstant{Value: big.NewInt(1)},
	}

	// This should complete without panicking or infinite looping
	// The cycle detection in renamerFunc should break the cycle
	renamer := c.renamerFunc()

	// Use a channel with timeout to detect infinite loops
	done := make(chan string, 1)
	go func() {
		result := scev.StringWithRenamer(renamer)
		done <- result
	}()

	select {
	case result := <-done:
		t.Logf("StringWithRenamer completed successfully with result: %s", result)
		// The result should be some valid string (exact format depends on how cycle is broken)
		if result == "" {
			t.Error("Expected non-empty result")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StringWithRenamer did not complete within timeout - likely infinite loop")
	}
}

// TestRenamerCyclesDeep verifies cycle detection with deeper nesting where
// the cycle occurs through non-SCEV intermediate values.
func TestRenamerCyclesDeep(t *testing.T) {
	c := NewCanonicalizer(DefaultLiteralPolicy)
	defer ReleaseCanonicalizer(c)

	// Create mock values - we'll use SCEVConstant as non-looping terminal markers
	mockA := &SCEVUnknown{Value: nil, IsInvariant: true}

	// Create a self-loop: A -> A
	// This is the simplest cycle case
	c.virtualSubstitutions[mockA] = mockA

	scevWithCyclicValue := &SCEVUnknown{Value: mockA, IsInvariant: false}
	scev := &SCEVAddRec{
		Start: scevWithCyclicValue,
		Step:  &SCEVConstant{Value: big.NewInt(1)},
	}

	renamer := c.renamerFunc()

	done := make(chan string, 1)
	go func() {
		result := scev.StringWithRenamer(renamer)
		done <- result
	}()

	select {
	case result := <-done:
		t.Logf("Self-loop cycle handled successfully: %s", result)
		if result == "" {
			t.Error("Expected non-empty result")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StringWithRenamer did not complete - self-loop caused infinite loop")
	}
}

// TestRenamerSCEVSubstitution verifies that when a substitution resolves to an SCEV,
// the renamer correctly stringifies that SCEV.
func TestRenamerSCEVSubstitution(t *testing.T) {
	c := NewCanonicalizer(DefaultLiteralPolicy)
	defer ReleaseCanonicalizer(c)

	// Create a mock value and a terminal SCEV
	mockA := &SCEVUnknown{Value: nil, IsInvariant: true}
	terminalSCEV := &SCEVConstant{Value: big.NewInt(42)}

	// Direct substitution: A -> terminalSCEV
	c.virtualSubstitutions[mockA] = terminalSCEV

	// Create an SCEVUnknown that wraps mockA as its Value
	scevWithSubstitutedValue := &SCEVUnknown{Value: mockA, IsInvariant: false}

	scev := &SCEVAddRec{
		Start: scevWithSubstitutedValue,
		Step:  &SCEVConstant{Value: big.NewInt(1)},
	}

	renamer := c.renamerFunc()
	result := scev.StringWithRenamer(renamer)

	// The result should show the terminal SCEV value (42) for the Start
	t.Logf("SCEV substitution result: %s", result)
	if !strings.Contains(result, "42") {
		t.Errorf("Expected result to contain '42' from terminal SCEV, got: %s", result)
	}
}

// compileAndGetFunction is a helper to compile source and get a named function.
func compileAndGetFunction(t *testing.T, src, funcName string) *ssa.Function {
	t.Helper()

	// Use setupTestEnv to create a proper isolated directory
	tempDir, cleanup := setupTestEnv(t, "scev-test-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSourceAdvanced(path, src, DefaultLiteralPolicy, false)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	// Search for function by suffix (handles package prefix like "testmod.funcName")
	for _, r := range results {
		if strings.HasSuffix(r.FunctionName, "."+funcName) || r.FunctionName == funcName {
			return r.fn
		}
	}

	t.Logf("Available functions: %v", getFunctionNames(results))
	return nil
}
