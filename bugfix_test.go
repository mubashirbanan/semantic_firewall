package semanticfw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestChangeInterface verifies that interface-to-interface conversions are handled.
func TestChangeInterface(t *testing.T) {
	src := `package main
import "io"

func changeInterface(r io.Reader) interface{} {
	return r // Converts io.Reader to interface{}
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-changeintf-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Should NOT panic in strict mode
	results, err := FingerprintSourceAdvanced(path, src, DefaultLiteralPolicy, true)
	if err != nil {
		t.Fatalf("FingerprintSourceAdvanced failed: %v", err)
	}

	res := findResult(results, "changeInterface")
	if res == nil {
		t.Fatal("Result for 'changeInterface' not found")
	}

	// Verify the ChangeInterface instruction is in the IR
	if !strings.Contains(res.CanonicalIR, "ChangeInterface") {
		t.Errorf("Expected ChangeInterface in IR.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestSliceToArrayPointer verifies slice-to-array-pointer conversions are handled.
func TestSliceToArrayPointer(t *testing.T) {
	src := `package main

func sliceToArray(s []int) *[4]int {
	if len(s) >= 4 {
		return (*[4]int)(s)
	}
	return nil
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-slice2arr-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Should NOT panic in strict mode
	results, err := FingerprintSourceAdvanced(path, src, DefaultLiteralPolicy, true)
	if err != nil {
		t.Fatalf("FingerprintSourceAdvanced failed: %v", err)
	}

	res := findResult(results, "sliceToArray")
	if res == nil {
		t.Fatal("Result for 'sliceToArray' not found")
	}

	// Verify the SliceToArrayPointer instruction is in the IR
	if !strings.Contains(res.CanonicalIR, "SliceToArrayPointer") {
		t.Errorf("Expected SliceToArrayPointer in IR.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestComplexNumberNormalization verifies that complex number comparisons are NOT normalized.
// Complex numbers have undefined ordering, similar to NaN for floats.
func TestComplexNumberNormalization(t *testing.T) {
	// We can test the fix indirectly by verifying float behavior still works
	src := `package main
import "math"

func checkFloat(a, b float64) bool {
	if a >= b {
		return true
	}
	return math.IsNaN(a)
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-complex-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(path, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	res := findResult(results, "checkFloat")
	if res == nil {
		t.Fatal("Result for 'checkFloat' not found")
	}

	// Float comparisons should NOT be normalized (>= should remain >=)
	if !strings.Contains(res.CanonicalIR, "BinOp >=") {
		t.Errorf("Expected BinOp >= to be preserved for float comparison (NaN safety).\nIR:\n%s", res.CanonicalIR)
	}
}

// TestDefensiveSuccessorCheck verifies the code handles edge cases gracefully.
// This tests that the defensive checks don't break normal operation.
func TestDefensiveSuccessorCheck(t *testing.T) {
	src := `package main

func normalBranching(x int) int {
	if x > 10 {
		return 1
	} else if x > 5 {
		return 2
	}
	return 0
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-defense-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(path, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	res := findResult(results, "normalBranching")
	if res == nil {
		t.Fatal("Result for 'normalBranching' not found")
	}

	// Should still produce valid IR with If instructions
	if !strings.Contains(res.CanonicalIR, "If ") {
		t.Errorf("Expected If instruction in IR.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestEmptyBlocksHandling verifies functions with empty blocks don't cause issues.
func TestEmptyBlocksHandling(t *testing.T) {
	src := `package main

func empty() {}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-empty-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(path, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	res := findResult(results, "empty")
	if res == nil {
		t.Fatal("Result for 'empty' not found")
	}

	// Should produce valid IR
	if !strings.Contains(res.CanonicalIR, "Return") {
		t.Errorf("Expected Return instruction in IR.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestMultipleInterfaceConversions verifies complex interface conversion chains.
func TestMultipleInterfaceConversions(t *testing.T) {
	src := `package main
import (
	"fmt"
	"io"
)

type MyReader struct{}
func (m *MyReader) Read(p []byte) (int, error) { return 0, nil }

func multiConvert(m *MyReader) {
	var r io.Reader = m      // MakeInterface
	var i interface{} = r    // ChangeInterface
	fmt.Println(i)
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-multiconv-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Should NOT panic in strict mode
	results, err := FingerprintSourceAdvanced(path, src, DefaultLiteralPolicy, true)
	if err != nil {
		t.Fatalf("FingerprintSourceAdvanced failed: %v", err)
	}

	res := findResult(results, "multiConvert")
	if res == nil {
		t.Fatal("Result for 'multiConvert' not found")
	}

	// Should contain both MakeInterface and ChangeInterface
	if !strings.Contains(res.CanonicalIR, "MakeInterface") {
		t.Errorf("Expected MakeInterface in IR.\nIR:\n%s", res.CanonicalIR)
	}
	if !strings.Contains(res.CanonicalIR, "ChangeInterface") {
		t.Errorf("Expected ChangeInterface in IR.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestAllNewInstructionsCombined tests all new instruction types in one function.
func TestAllNewInstructionsCombined(t *testing.T) {
	src := `package main
import "io"

func combined(r io.Reader, s []int) (interface{}, *[2]int) {
	var i interface{} = r // ChangeInterface (io.Reader -> interface{})
	var arr *[2]int
	if len(s) >= 2 {
		arr = (*[2]int)(s) // SliceToArrayPointer
	}
	return i, arr
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-combined-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Should NOT panic in strict mode
	results, err := FingerprintSourceAdvanced(path, src, DefaultLiteralPolicy, true)
	if err != nil {
		t.Fatalf("FingerprintSourceAdvanced failed: %v", err)
	}

	res := findResult(results, "combined")
	if res == nil {
		t.Fatal("Result for 'combined' not found")
	}

	// Both new instruction types should be handled
	if !strings.Contains(res.CanonicalIR, "ChangeInterface") {
		t.Errorf("Expected ChangeInterface in IR.\nIR:\n%s", res.CanonicalIR)
	}
	if !strings.Contains(res.CanonicalIR, "SliceToArrayPointer") {
		t.Errorf("Expected SliceToArrayPointer in IR.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestLoopIncrementSinking verifies that range and index loops produce
// identical fingerprints when they are semantically equivalent.
// Range loops: Go generates pre-increment form (iterator starts at -1, +1 to get index)
// Index loops: Use direct index (starts at 0)
// With SCEV normalization, these should produce identical fingerprints because
// the derived IV (v1+1 in range loop) folds to the same {0, +, 1} as the direct IV.
func TestLoopIncrementSinking(t *testing.T) {
	// Two functions with different loop structures:
	// V1: Range-based loop (Go generates pre-increment pattern)
	// V2: Index-based for loop (post-increment pattern)
	src := `package main

// V1: Range loop - Go generates pre-increment form
func rangeLoop(items []int) int {
	var total int
	for _, item := range items {
		total += item
	}
	return total
}

// V2: Index loop - standard post-increment form
func indexLoop(items []int) int {
	var total int
	for i := 0; i < len(items); i++ {
		total += items[i]
	}
	return total
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-loopincr-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSourceAdvanced(path, src, DefaultLiteralPolicy, true)
	if err != nil {
		t.Fatalf("FingerprintSourceAdvanced failed: %v", err)
	}

	res1 := findResult(results, "rangeLoop")
	res2 := findResult(results, "indexLoop")

	if res1 == nil || res2 == nil {
		t.Fatalf("Could not find results for test functions. Found: %v", getFunctionNames(results))
	}

	// Verify both functions produce valid canonical IR with proper loop structure
	validateLoopIR := func(ir, funcName string) {
		lines := strings.Split(ir, "\n")
		hasHeader := false
		hasBody := false
		hasExit := false
		hasSCEV := false

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "b1:") {
				hasHeader = true
			}
			if strings.HasPrefix(trimmed, "b2:") {
				hasBody = true
			}
			if strings.HasPrefix(trimmed, "b3:") {
				hasExit = true
			}
			// Check for SCEV normalization (induction variable represented as {start, +, step})
			if strings.Contains(trimmed, "{") && strings.Contains(trimmed, ", +, ") {
				hasSCEV = true
			}
		}

		if !hasHeader {
			t.Errorf("%s: Missing header block (b1)\nIR:\n%s", funcName, ir)
		}
		if !hasBody {
			t.Errorf("%s: Missing body block (b2)\nIR:\n%s", funcName, ir)
		}
		if !hasExit {
			t.Errorf("%s: Missing exit block (b3)\nIR:\n%s", funcName, ir)
		}
		if !hasSCEV {
			t.Errorf("%s: Missing SCEV normalization (expected {start, +, step} form)\nIR:\n%s", funcName, ir)
		}
	}

	validateLoopIR(res1.CanonicalIR, "rangeLoop")
	validateLoopIR(res2.CanonicalIR, "indexLoop")

	// Verify both functions produce non-empty fingerprints
	if res1.Fingerprint == "" {
		t.Errorf("rangeLoop: Empty fingerprint")
	}
	if res2.Fingerprint == "" {
		t.Errorf("indexLoop: Empty fingerprint")
	}

	// With SCEV normalization propagating to derived values, range and index loops
	// that are semantically equivalent should now produce identical fingerprints.
	// The range loop's {-1, +, 1} + 1 folds to {0, +, 1}, matching the index loop.
	if res1.Fingerprint != res2.Fingerprint {
		t.Errorf("Expected identical fingerprints for semantically equivalent loops\n"+
			"rangeLoop fingerprint: %s\nindexLoop fingerprint: %s\n"+
			"rangeLoop IR:\n%s\nindexLoop IR:\n%s",
			res1.Fingerprint, res2.Fingerprint, res1.CanonicalIR, res2.CanonicalIR)
	}

	t.Logf("rangeLoop fingerprint: %s", res1.Fingerprint)
	t.Logf("indexLoop fingerprint: %s", res2.Fingerprint)
}

// TestFloatComparisonRightOperand verifies that float comparisons are NOT normalized
// when the float is on the RIGHT side of the comparison (e.g., "0 >= floatVar").
func TestFloatComparisonRightOperand(t *testing.T) {
	// This test specifically targets the bug where "const >= floatVar" would be
	// incorrectly normalized because only binOp.X was checked for float type.
	src := `package main

func checkFloatRight(f float64) bool {
	// Here, the LEFT operand is an int constant (0), and RIGHT is float64.
	// The comparison should NOT be normalized because floats have NaN issues.
	if 0 >= f {
		return true
	}
	return false
}

func checkFloatLeft(f float64) bool {
	// Here, the LEFT operand is float64.
	// This should also NOT be normalized.
	if f >= 0 {
		return true
	}
	return false
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-float-right-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(path, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	// Test 1: Float on RIGHT side (the bug fix)
	resRight := findResult(results, "checkFloatRight")
	if resRight == nil {
		t.Fatal("Result for 'checkFloatRight' not found")
	}

	// The comparison should NOT be normalized (>= should remain >=)
	// If the bug exists, it would be normalized to < because only left operand was checked.
	if !strings.Contains(resRight.CanonicalIR, "BinOp >=") {
		t.Errorf("BUG: Float comparison with float on RIGHT side was incorrectly normalized.\n"+
			"Expected BinOp >= to be preserved (NaN safety).\nIR:\n%s", resRight.CanonicalIR)
	}
	if strings.Contains(resRight.CanonicalIR, "BinOp <") {
		t.Errorf("BUG: Found 'BinOp <' which indicates incorrect normalization.\n"+
			"Float comparisons should not be normalized.\nIR:\n%s", resRight.CanonicalIR)
	}

	// Test 2: Float on LEFT side (existing behavior, should still work)
	resLeft := findResult(results, "checkFloatLeft")
	if resLeft == nil {
		t.Fatal("Result for 'checkFloatLeft' not found")
	}

	if !strings.Contains(resLeft.CanonicalIR, "BinOp >=") {
		t.Errorf("Float comparison with float on LEFT side was incorrectly normalized.\n"+
			"Expected BinOp >= to be preserved.\nIR:\n%s", resLeft.CanonicalIR)
	}
}

// TestIntComparisonStillNormalized verifies that integer comparisons are still normalized
// after the float fix (regression test).
func TestIntComparisonStillNormalized(t *testing.T) {
	src := `package main

func checkInt(a, b int) bool {
	// Integer >= comparison SHOULD be normalized to <
	if a >= b {
		return true
	}
	return false
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-int-norm-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(path, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	res := findResult(results, "checkInt")
	if res == nil {
		t.Fatal("Result for 'checkInt' not found")
	}

	// Integer comparisons SHOULD still be normalized (>= becomes <)
	if !strings.Contains(res.CanonicalIR, "BinOp <") {
		t.Errorf("Integer comparison should be normalized to BinOp <.\nIR:\n%s", res.CanonicalIR)
	}
	if strings.Contains(res.CanonicalIR, "BinOp >=") {
		t.Errorf("Integer comparison should NOT contain BinOp >= after normalization.\nIR:\n%s", res.CanonicalIR)
	}
}
