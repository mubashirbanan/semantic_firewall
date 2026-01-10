package semanticfw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBugFixes verifies that the critical bugs identified are resolved.
func TestBugFixes(t *testing.T) {
	policy := DefaultLiteralPolicy

	t.Run("Bug1_LoopInvariantHoisting", func(t *testing.T) {
		// -- Setup Isolated Environment --
		tempDir, cleanup := setupTestEnv(t, "bug1-")
		defer cleanup()

		// This code contains a loop with an invariant call `len(s)`.
		// Without the fix, this call remains in the loop (b1).
		// With the fix, it should be hoisted to the pre-header (b0).
		src := `package semanticfw
		func testLoop(s string) int {
			sum := 0
			for i := 0; i < 10; i++ {
				sum += len(s)
			}
			return sum
		}`

		path := filepath.Join(tempDir, "test.go")
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}

		results, err := FingerprintSource(path, src, policy)
		if err != nil {
			t.Fatalf("Analysis failed: %v", err)
		}

		// FIX: Use findResult instead of hardcoding index 0.
		// The results may now contain synthetic init functions.
		res := findResult(results, "testLoop")
		if res == nil {
			t.Fatalf("Function 'testLoop' not found in results: %v", getFunctionNames(results))
		}

		ir := res.CanonicalIR

		// We expect "Call <builtin:len>" appearing BEFORE "b1:" (the loop header).
		block1Index := strings.Index(ir, "b1:")
		callLenIndex := strings.Index(ir, "Call <builtin:len>")

		if block1Index == -1 || callLenIndex == -1 {
			t.Fatalf("IR missing critical structures:\n%s", ir)
		}

		if callLenIndex > block1Index {
			t.Errorf("BUG 1 REPRODUCED: Invariant len() call found inside loop.\nExpected it hoisted to pre-header.\nIR:\n%s", ir)
		}
	})

	t.Run("Bug2_InductionVariableNormalization", func(t *testing.T) {
		// -- Setup Isolated Environment --
		tempDir, cleanup := setupTestEnv(t, "bug2-")
		defer cleanup()

		// FIX: The -1 to 0 normalization was removed because it caused semantic corruption.
		// This test now verifies that 0-indexed loops have their increment sunk to the latch block.
		// We test a standard 0-indexed loop instead of a -1 loop.
		src := `package main
		func test() {
			for i := 0; i < 10; i++ {}
		}`

		path := filepath.Join(tempDir, "test.go")
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}

		results, err := FingerprintSource(path, src, policy)
		if err != nil {
			t.Fatalf("Analysis failed: %v", err)
		}

		// FIX: Use findResult to target the specific function.
		res := findResult(results, "test")
		if res == nil {
			t.Fatalf("Function 'test' not found in results: %v", getFunctionNames(results))
		}

		ir := res.CanonicalIR

		// Verify the loop starts at 0 using SCEV notation
		// After IV normalization, the Phi is replaced with {Start, +, Step}
		if !strings.Contains(ir, "{0, +, 1}") {
			t.Errorf("Expected SCEV notation {0, +, 1} in IR for 0-indexed loop.\nIR:\n%s", ir)
		}
	})

	t.Run("Bug3_StringCommutativity", func(t *testing.T) {
		// -- Setup Isolated Environment --
		tempDir, cleanup := setupTestEnv(t, "bug3-")
		defer cleanup()

		// String concatenation is not commutative.
		// s1 and s2 should produce DIFFERENT fingerprints.
		src := `package main
		func s1(a, b string) string { return a + b }
		func s2(a, b string) string { return b + a }
		`
		path := filepath.Join(tempDir, "test.go")
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}

		results, err := FingerprintSource(path, src, policy)
		if err != nil {
			t.Fatalf("Analysis failed: %v", err)
		}

		// FIX: Use findResult for both functions.
		res1 := findResult(results, "s1")
		res2 := findResult(results, "s2")

		if res1 == nil || res2 == nil {
			t.Fatalf("Expected results for s1 and s2, got %v", getFunctionNames(results))
		}

		fp1 := res1.Fingerprint
		fp2 := res2.Fingerprint

		if fp1 == fp2 {
			t.Errorf("BUG 3 REPRODUCED: String concatenation treated as commutative.\nFingerprints are identical: %s", fp1)
		}
	})
}
