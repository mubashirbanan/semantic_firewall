package semanticfw

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SECTION 1: Source Code Compilation Fuzzing

// FuzzSourceCodeAnalysis tests the framework's ability to handle various Go source
// code patterns without panicking during SSA construction and analysis.
func FuzzSourceCodeAnalysis(f *testing.F) {
	// Valid Go function patterns
	f.Add(`package main
func main() {
	println("hello")
}`)

	f.Add(`package main
func add(a, b int) int {
	return a + b
}
func main() {
	add(1, 2)
}`)

	// Loop patterns
	f.Add(`package main
func main() {
	for i := 0; i < 10; i++ {
		println(i)
	}
}`)

	f.Add(`package main
func main() {
	i := 0
	for {
		if i > 10 {
			break
		}
		i++
	}
}`)

	// Control flow patterns
	f.Add(`package main
func main() {
	x := 5
	if x > 3 {
		println("big")
	} else {
		println("small")
	}
}`)

	f.Add(`package main
func main() {
	switch x := 1; x {
	case 1:
		println("one")
	case 2:
		println("two")
	default:
		println("other")
	}
}`)

	// Function with multiple returns
	f.Add(`package main
func divide(a, b int) (int, error) {
	if b == 0 {
		return 0, nil
	}
	return a / b, nil
}
func main() {
	divide(10, 2)
}`)

	// Closure pattern
	f.Add(`package main
func main() {
	f := func(x int) int {
		return x * 2
	}
	f(5)
}`)

	// Defer/recover pattern
	f.Add(`package main
func safe() {
	defer func() {
		recover()
	}()
	panic("test")
}
func main() {
	safe()
}`)

	// Goroutine pattern
	f.Add(`package main
func main() {
	go func() {
		println("async")
	}()
}`)

	// Select pattern
	f.Add(`package main
func main() {
	c := make(chan int, 1)
	c <- 1
	select {
	case x := <-c:
		println(x)
	default:
		println("default")
	}
}`)

	// Range pattern
	f.Add(`package main
func main() {
	for i, v := range []int{1, 2, 3} {
		println(i, v)
	}
}`)

	// Method pattern
	f.Add(`package main
type Counter struct {
	count int
}
func (c *Counter) Inc() {
	c.count++
}
func main() {
	c := &Counter{}
	c.Inc()
}`)

	f.Fuzz(func(t *testing.T, source string) {
		// Skip empty or very short inputs
		if len(source) < 10 {
			return
		}

		// Skip if it doesn't start with package declaration
		if !strings.HasPrefix(strings.TrimSpace(source), "package") {
			return
		}

		// Create temp directory with source file
		tempDir, cleanup := SetupTestEnv(t, "fuzz_source_*")
		defer cleanup()

		srcPath := filepath.Join(tempDir, "main.go")
		if err := os.WriteFile(srcPath, []byte(source), 0644); err != nil {
			return
		}

		// Try to fingerprint - should not panic
		results, err := FingerprintSource(srcPath, source, DefaultLiteralPolicy)
		if err != nil {
			// Compilation errors are expected for invalid Go code
			return
		}

		// If we got results, verify they're valid
		for _, r := range results {
			if r.Fingerprint == "" {
				t.Errorf("Got empty fingerprint for function %s", r.FunctionName)
			}
		}
	})
}

// SECTION 2: Fingerprint Comparison Fuzzing

// FuzzFingerprintStability tests that fingerprints are stable across multiple runs.
func FuzzFingerprintStability(f *testing.F) {
	f.Add(`package main
func target(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func main() { target(1, 2) }`)

	f.Add(`package main
func loop() int {
	sum := 0
	for i := 0; i < 100; i++ {
		sum += i
	}
	return sum
}
func main() { loop() }`)

	f.Fuzz(func(t *testing.T, source string) {
		if len(source) < 20 || !strings.HasPrefix(strings.TrimSpace(source), "package") {
			return
		}

		tempDir, cleanup := SetupTestEnv(t, "fuzz_stability_*")
		defer cleanup()

		srcPath := filepath.Join(tempDir, "main.go")
		if err := os.WriteFile(srcPath, []byte(source), 0644); err != nil {
			return
		}

		// Run fingerprinting twice
		results1, err1 := FingerprintSource(srcPath, source, DefaultLiteralPolicy)
		results2, err2 := FingerprintSource(srcPath, source, DefaultLiteralPolicy)

		if err1 != nil || err2 != nil {
			return
		}

		// Fingerprints should be identical
		if len(results1) != len(results2) {
			t.Errorf("Different number of results: %d vs %d", len(results1), len(results2))
			return
		}

		for i := range results1 {
			if results1[i].Fingerprint != results2[i].Fingerprint {
				t.Errorf("Fingerprint mismatch for %s: %s vs %s",
					results1[i].FunctionName, results1[i].Fingerprint, results2[i].Fingerprint)
			}
		}
	})
}

// SECTION 3: Topology Extraction Fuzzing

// FuzzTopologyExtraction tests topology extraction from SSA functions.
func FuzzTopologyExtraction(f *testing.F) {
	f.Add(`package main
func simple() {
	x := 1
	_ = x
}
func main() { simple() }`)

	f.Add(`package main
func complex(a, b, c int) (int, bool) {
	if a > 0 {
		for i := 0; i < b; i++ {
			a += c
		}
		return a, true
	}
	return 0, false
}
func main() { complex(1, 2, 3) }`)

	f.Add(`package main
func recursive(n int) int {
	if n <= 1 {
		return 1
	}
	return n * recursive(n-1)
}
func main() { recursive(5) }`)

	f.Fuzz(func(t *testing.T, source string) {
		if len(source) < 20 || !strings.HasPrefix(strings.TrimSpace(source), "package") {
			return
		}

		tempDir, cleanup := SetupTestEnv(t, "fuzz_topo_*")
		defer cleanup()

		srcPath := filepath.Join(tempDir, "main.go")
		if err := os.WriteFile(srcPath, []byte(source), 0644); err != nil {
			return
		}

		results, err := FingerprintSource(srcPath, source, DefaultLiteralPolicy)
		if err != nil {
			return
		}

		for _, r := range results {
			fn := r.GetSSAFunction()
			if fn == nil {
				continue
			}

			// Extract topology - should not panic
			topo := ExtractTopology(fn)
			if topo == nil {
				continue
			}

			// Validate topology fields
			if topo.BlockCount < 0 {
				t.Errorf("Negative block count: %d", topo.BlockCount)
			}
			if topo.InstrCount < 0 {
				t.Errorf("Negative instruction count: %d", topo.InstrCount)
			}
			if topo.ParamCount < 0 {
				t.Errorf("Negative param count: %d", topo.ParamCount)
			}

			// Fuzzy hash should be generated
			if topo.FuzzyHash == "" {
				t.Error("Empty fuzzy hash")
			}
		}
	})
}

// SECTION 4: Scanner Integration Fuzzing

// FuzzScannerIntegration tests the full scan pipeline.
func FuzzScannerIntegration(f *testing.F) {
	f.Add(`package main
import (
	"fmt"
	"time"
)
func beacon() {
	for {
		fmt.Println("ping")
		time.Sleep(time.Second)
	}
}
func main() { beacon() }`, "BEACON-001", "Beacon Pattern", "HIGH", "backdoor")

	f.Add(`package main
func innocent() int {
	return 42
}
func main() { innocent() }`, "CLEAN-001", "Clean Function", "LOW", "benign")

	f.Fuzz(func(t *testing.T, source, sigID, sigName, severity, category string) {
		if len(source) < 20 || !strings.HasPrefix(strings.TrimSpace(source), "package") {
			return
		}

		tempDir, cleanup := SetupTestEnv(t, "fuzz_scanner_*")
		defer cleanup()

		srcPath := filepath.Join(tempDir, "main.go")
		if err := os.WriteFile(srcPath, []byte(source), 0644); err != nil {
			return
		}

		results, err := FingerprintSource(srcPath, source, DefaultLiteralPolicy)
		if err != nil {
			return
		}

		scanner := NewScanner()

		for _, r := range results {
			fn := r.GetSSAFunction()
			if fn == nil {
				continue
			}

			topo := ExtractTopology(fn)
			if topo == nil {
				continue
			}

			// Index the function to create a signature
			sig := IndexFunction(topo, sigName, "Fuzz test signature", severity, category)
			sig.ID = sigID

			// Create a database with just this signature
			scanner.db = &SignatureDatabase{
				Signatures: []Signature{sig},
			}

			// Scan should not panic
			scanResults := scanner.ScanTopology(topo, r.FunctionName)
			_ = scanResults
		}
	})
}

// SECTION 5: Zipper/Delta Analysis Fuzzing

// FuzzZipperAnalysis tests the semantic diff algorithm with pairs of functions.
func FuzzZipperAnalysis(f *testing.F) {
	// Identical functions
	f.Add(`package main
func target(x int) int { return x + 1 }
func main() { target(1) }`,
		`package main
func target(x int) int { return x + 1 }
func main() { target(1) }`, "target")

	// Different constants
	f.Add(`package main
func target(x int) int { return x + 1 }
func main() { target(1) }`,
		`package main
func target(x int) int { return x + 2 }
func main() { target(1) }`, "target")

	// Added statement
	f.Add(`package main
func target(x int) int { return x }
func main() { target(1) }`,
		`package main
func target(x int) int { y := x * 2; return y }
func main() { target(1) }`, "target")

	f.Fuzz(func(t *testing.T, source1, source2, funcName string) {
		if len(source1) < 20 || len(source2) < 20 {
			return
		}
		if !strings.HasPrefix(strings.TrimSpace(source1), "package") ||
			!strings.HasPrefix(strings.TrimSpace(source2), "package") {
			return
		}
		if funcName == "" || funcName == "main" || funcName == "init" {
			return
		}

		// Setup first version
		tempDir1, cleanup1 := SetupTestEnv(t, "fuzz_zip1_*")
		defer cleanup1()

		srcPath1 := filepath.Join(tempDir1, "main.go")
		if err := os.WriteFile(srcPath1, []byte(source1), 0644); err != nil {
			return
		}

		// Setup second version
		tempDir2, cleanup2 := SetupTestEnv(t, "fuzz_zip2_*")
		defer cleanup2()

		srcPath2 := filepath.Join(tempDir2, "main.go")
		if err := os.WriteFile(srcPath2, []byte(source2), 0644); err != nil {
			return
		}

		// Get results for both versions
		results1, err1 := FingerprintSource(srcPath1, source1, DefaultLiteralPolicy)
		results2, err2 := FingerprintSource(srcPath2, source2, DefaultLiteralPolicy)

		if err1 != nil || err2 != nil {
			return
		}

		// Find target function in both
		var fn1, fn2 *FingerprintResult
		for i := range results1 {
			if strings.Contains(results1[i].FunctionName, funcName) {
				fn1 = &results1[i]
				break
			}
		}
		for i := range results2 {
			if strings.Contains(results2[i].FunctionName, funcName) {
				fn2 = &results2[i]
				break
			}
		}

		if fn1 == nil || fn2 == nil {
			return
		}

		ssaFn1 := fn1.GetSSAFunction()
		ssaFn2 := fn2.GetSSAFunction()

		if ssaFn1 == nil || ssaFn2 == nil {
			return
		}

		// Create zipper and compute diff - should not panic
		zipper, err := NewZipper(ssaFn1, ssaFn2, DefaultLiteralPolicy)
		if err != nil {
			return
		}

		artifacts, err := zipper.ComputeDiff()
		if err != nil {
			return
		}

		// Validate artifacts
		if artifacts == nil {
			t.Error("Got nil artifacts from ComputeDiff")
			return
		}

		if artifacts.MatchedNodes < 0 {
			t.Errorf("Negative matched nodes: %d", artifacts.MatchedNodes)
		}
	})
}

// SECTION 6: Loop Detection Fuzzing

// FuzzLoopDetection tests the loop detection algorithm.
func FuzzLoopDetection(f *testing.F) {
	// Simple for loop
	f.Add(`package main
func loops() {
	for i := 0; i < 10; i++ {
		println(i)
	}
}
func main() { loops() }`)

	// Nested loops
	f.Add(`package main
func nested() {
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			println(i, j)
		}
	}
}
func main() { nested() }`)

	// While-style loop
	f.Add(`package main
func whileStyle() {
	i := 0
	for i < 10 {
		i++
	}
}
func main() { whileStyle() }`)

	// Infinite loop with break
	f.Add(`package main
func infLoop() {
	for {
		if true {
			break
		}
	}
}
func main() { infLoop() }`)

	f.Fuzz(func(t *testing.T, source string) {
		if len(source) < 20 || !strings.HasPrefix(strings.TrimSpace(source), "package") {
			return
		}

		tempDir, cleanup := SetupTestEnv(t, "fuzz_loops_*")
		defer cleanup()

		srcPath := filepath.Join(tempDir, "main.go")
		if err := os.WriteFile(srcPath, []byte(source), 0644); err != nil {
			return
		}

		results, err := FingerprintSource(srcPath, source, DefaultLiteralPolicy)
		if err != nil {
			return
		}

		for _, r := range results {
			fn := r.GetSSAFunction()
			if fn == nil {
				continue
			}

			// Detect loops - should not panic
			loopInfo := DetectLoops(fn)
			if loopInfo == nil {
				t.Error("Got nil LoopInfo")
				continue
			}

			// Validate loop structure
			for _, loop := range loopInfo.Loops {
				if loop.Header == nil {
					t.Error("Loop with nil header")
				}
				if loop.Blocks == nil {
					t.Error("Loop with nil blocks map")
				}
			}
		}
	})
}

// SECTION 7: Canonical IR Generation Fuzzing

// FuzzCanonicalIRGeneration tests the canonical IR generation.
func FuzzCanonicalIRGeneration(f *testing.F) {
	f.Add(`package main
func simple(x int) int {
	y := x + 1
	return y
}
func main() { simple(1) }`, false)

	f.Add(`package main
func complex(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}
func main() { complex(1, 2) }`, true)

	f.Fuzz(func(t *testing.T, source string, strictMode bool) {
		if len(source) < 20 || !strings.HasPrefix(strings.TrimSpace(source), "package") {
			return
		}

		tempDir, cleanup := SetupTestEnv(t, "fuzz_canon_*")
		defer cleanup()

		srcPath := filepath.Join(tempDir, "main.go")
		if err := os.WriteFile(srcPath, []byte(source), 0644); err != nil {
			return
		}

		results, err := FingerprintSource(srcPath, source, DefaultLiteralPolicy)
		if err != nil {
			return
		}

		for _, r := range results {
			fn := r.GetSSAFunction()
			if fn == nil {
				continue
			}

			// Generate fingerprint with specific settings - should not panic
			result := GenerateFingerprint(fn, DefaultLiteralPolicy, strictMode)

			// Canonical IR should not be empty for valid functions
			if len(fn.Blocks) > 0 && result.CanonicalIR == "" {
				t.Logf("Warning: empty canonical IR for function %s", r.FunctionName)
			}

			// Fingerprint should be deterministic
			result2 := GenerateFingerprint(fn, DefaultLiteralPolicy, strictMode)
			if result.Fingerprint != result2.Fingerprint {
				t.Errorf("Non-deterministic fingerprint for %s", r.FunctionName)
			}
		}
	})
}

// SECTION 8: Signature Serialization Round-Trip Fuzzing

// FuzzSignatureRoundTrip tests JSON serialization/deserialization of signatures.
func FuzzSignatureRoundTrip(f *testing.F) {
	f.Add("SIG-001", "Test Signature", "A test", "HIGH", "backdoor",
		"abc123", "B2L1BR1", 5.5, 0.5, 10, 2)

	f.Add("", "", "", "", "", "", "", 0.0, 0.0, 0, 0)

	f.Add(strings.Repeat("X", 1000), "Name", "Desc", "CRITICAL", "malware",
		"hash", "fuzz", 7.5, 0.1, 100, 10)

	f.Fuzz(func(t *testing.T, id, name, desc, severity, category,
		topoHash, fuzzyHash string, entropy, tolerance float64,
		nodeCount, loopDepth int) {

		sig := Signature{
			ID:               id,
			Name:             name,
			Description:      desc,
			Severity:         severity,
			Category:         category,
			TopologyHash:     topoHash,
			FuzzyHash:        fuzzyHash,
			EntropyScore:     entropy,
			EntropyTolerance: tolerance,
			NodeCount:        nodeCount,
			LoopDepth:        loopDepth,
			IdentifyingFeatures: IdentifyingFeatures{
				RequiredCalls:  []string{"test.Call"},
				StringPatterns: []string{"pattern"},
			},
		}

		// Serialize
		data, err := json.Marshal(sig)
		if err != nil {
			// Some values may not serialize (e.g., NaN)
			return
		}

		// Deserialize
		var decoded Signature
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Errorf("Failed to unmarshal serialized signature: %v", err)
			return
		}

		// Verify key fields survived round-trip
		if decoded.ID != sig.ID {
			t.Errorf("ID mismatch: got %q, want %q", decoded.ID, sig.ID)
		}
		if decoded.Name != sig.Name {
			t.Errorf("Name mismatch: got %q, want %q", decoded.Name, sig.Name)
		}
		if decoded.TopologyHash != sig.TopologyHash {
			t.Errorf("TopologyHash mismatch: got %q, want %q", decoded.TopologyHash, sig.TopologyHash)
		}
	})
}

// SECTION 9: Large Function Handling Fuzzing

// FuzzLargeFunctionHandling tests handling of functions with many blocks/instructions.
func FuzzLargeFunctionHandling(f *testing.F) {
	// Generate a function with many branches
	f.Add(10)  // 10 branches
	f.Add(50)  // 50 branches
	f.Add(100) // 100 branches

	f.Fuzz(func(t *testing.T, branches int) {
		if branches < 1 || branches > 200 {
			branches = 10
		}

		// Generate source with many branches
		var sb strings.Builder
		sb.WriteString("package main\n\nfunc manyBranches(x int) int {\n")

		for i := 0; i < branches; i++ {
			sb.WriteString("  if x > ")
			sb.WriteString(string(rune('0' + (i % 10))))
			sb.WriteString(" {\n")
			sb.WriteString("    x++\n")
			sb.WriteString("  }\n")
		}

		sb.WriteString("  return x\n}\n\nfunc main() { manyBranches(0) }\n")

		source := sb.String()

		tempDir, cleanup := SetupTestEnv(t, "fuzz_large_*")
		defer cleanup()

		srcPath := filepath.Join(tempDir, "main.go")
		if err := os.WriteFile(srcPath, []byte(source), 0644); err != nil {
			return
		}

		// Should handle large functions without panic or timeout
		results, err := FingerprintSource(srcPath, source, DefaultLiteralPolicy)
		if err != nil {
			return
		}

		for _, r := range results {
			if strings.Contains(r.FunctionName, "manyBranches") {
				if r.Fingerprint == "" {
					t.Error("Empty fingerprint for large function")
				}

				fn := r.GetSSAFunction()
				if fn != nil {
					topo := ExtractTopology(fn)
					if topo != nil && topo.BranchCount < branches/2 {
						// We expect at least half the branches to be detected
						// (some may be optimized away)
						t.Logf("Warning: fewer branches than expected: %d < %d",
							topo.BranchCount, branches/2)
					}
				}
			}
		}
	})
}

// SECTION 10: Policy Variations Fuzzing

// FuzzPolicyVariations tests fingerprinting with different policy configurations.
func FuzzPolicyVariations(f *testing.F) {
	f.Add(`package main
func target(x int) int {
	const magic = 12345
	return x + magic
}
func main() { target(1) }`, true, true, true, true, int64(-100), int64(100))

	f.Add(`package main
func target() string {
	return "hello world"
}
func main() { target() }`, false, false, false, false, int64(0), int64(0))

	f.Fuzz(func(t *testing.T, source string, abstractCF, keepSmall, keepReturn, keepString bool,
		smallMin, smallMax int64) {

		if len(source) < 20 || !strings.HasPrefix(strings.TrimSpace(source), "package") {
			return
		}

		policy := LiteralPolicy{
			AbstractControlFlowComparisons: abstractCF,
			KeepSmallIntegerIndices:        keepSmall,
			KeepReturnStatusValues:         keepReturn,
			KeepStringLiterals:             keepString,
			SmallIntMin:                    smallMin,
			SmallIntMax:                    smallMax,
			AbstractOtherTypes:             true,
		}

		tempDir, cleanup := SetupTestEnv(t, "fuzz_policy_*")
		defer cleanup()

		srcPath := filepath.Join(tempDir, "main.go")
		if err := os.WriteFile(srcPath, []byte(source), 0644); err != nil {
			return
		}

		// Should not panic with any policy configuration
		results, err := FingerprintSourceAdvanced(srcPath, source, policy, false)
		if err != nil {
			return
		}

		for _, r := range results {
			if r.Fingerprint == "" {
				t.Errorf("Empty fingerprint for %s with custom policy", r.FunctionName)
			}
		}
	})
}
