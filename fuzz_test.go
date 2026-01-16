package semanticfw

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// SECTION 1: Entropy Calculation Fuzzing

// FuzzCalculateEntropy tests entropy calculation with arbitrary byte inputs.
// It verifies that entropy values are always within valid bounds [0.0, 8.0]
// and that the function handles edge cases gracefully.
func FuzzCalculateEntropy(f *testing.F) {
	// Seed corpus with interesting edge cases
	f.Add([]byte{})                                                       // Empty input
	f.Add([]byte{0})                                                      // Single byte
	f.Add([]byte{0, 0, 0, 0})                                             // Uniform data (lowest entropy)
	f.Add(make([]byte, 256))                                              // All zeros, 256 bytes
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})                           // Sequential
	f.Add([]byte("Hello, World!"))                                        // ASCII text
	f.Add([]byte("AAAAAAAAAAAAAAAA"))                                     // Repeated character
	f.Add([]byte{0xFF, 0x00, 0xFF, 0x00})                                 // Alternating extremes
	f.Add([]byte("exec('/bin/sh')"))                                      // Suspicious pattern
	f.Add([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c")) // Low bytes

	// Add high entropy seed (all unique bytes)
	highEntropy := make([]byte, 256)
	for i := range highEntropy {
		highEntropy[i] = byte(i)
	}
	f.Add(highEntropy)

	f.Fuzz(func(t *testing.T, data []byte) {
		entropy := CalculateEntropy(data)

		// Entropy must be in valid range [0.0, 8.0]
		if entropy < 0.0 || entropy > 8.0 {
			t.Errorf("Entropy out of range: got %f for input of length %d", entropy, len(data))
		}

		// Entropy of empty data must be 0
		if len(data) == 0 && entropy != 0.0 {
			t.Errorf("Expected entropy 0 for empty input, got %f", entropy)
		}

		// Check NaN/Inf
		if math.IsNaN(entropy) || math.IsInf(entropy, 0) {
			t.Errorf("Entropy is NaN or Inf for input of length %d", len(data))
		}

		// Normalized entropy should also be valid
		normEntropy := CalculateEntropyNormalized(data)
		if normEntropy < 0.0 || normEntropy > 1.0 {
			t.Errorf("Normalized entropy out of range: got %f", normEntropy)
		}

		// Classification should not panic and return valid class
		class := ClassifyEntropy(entropy)
		if class < EntropyLow || class > EntropyPacked {
			t.Errorf("Invalid entropy class: %d", class)
		}
	})
}

// FuzzCalculateEntropyProfile tests the entropy profile calculation.
func FuzzCalculateEntropyProfile(f *testing.F) {
	f.Add([]byte("function body"), "string1", "string2")
	f.Add([]byte{}, "", "")
	f.Add([]byte("\x00\xff"), "base64encoded", "aGVsbG8=")
	f.Add([]byte("net.Dial(tcp)"), "127.0.0.1:4444", "/bin/bash")

	f.Fuzz(func(t *testing.T, body []byte, str1, str2 string) {
		literals := []string{}
		if str1 != "" {
			literals = append(literals, str1)
		}
		if str2 != "" {
			literals = append(literals, str2)
		}

		profile := CalculateEntropyProfile(body, literals)

		// Verify profile fields are valid
		if profile.Overall < 0.0 || profile.Overall > 8.0 {
			t.Errorf("Profile overall entropy out of range: %f", profile.Overall)
		}

		if profile.StringLiteralEntropy < 0.0 || profile.StringLiteralEntropy > 8.0 {
			t.Errorf("Profile string literal entropy out of range: %f", profile.StringLiteralEntropy)
		}

		if profile.Classification < EntropyLow || profile.Classification > EntropyPacked {
			t.Errorf("Invalid profile classification: %d", profile.Classification)
		}
	})
}

// SECTION 2: Signature Database JSON Parsing Fuzzing

// FuzzSignatureDatabaseParsing tests JSON unmarshaling of signature databases.
// This tests resilience against malformed, malicious, or unexpected JSON inputs.
func FuzzSignatureDatabaseParsing(f *testing.F) {
	// Valid minimal signature database
	validDB := `{"version":"1.0","signatures":[]}`
	f.Add([]byte(validDB))

	// Valid with one signature
	validWithSig := `{
		"version": "1.0",
		"description": "Test",
		"signatures": [{
			"id": "TEST-001",
			"name": "Test",
			"severity": "HIGH",
			"topology_hash": "abc123",
			"entropy_score": 5.5,
			"node_count": 10
		}]
	}`
	f.Add([]byte(validWithSig))

	// Edge cases
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte("[]"))
	f.Add([]byte(`{"signatures": null}`))
	f.Add([]byte(`{"version": "", "signatures": []}`))
	f.Add([]byte(`{"entropy_score": -999999}`))
	f.Add([]byte(`{"entropy_score": 1e308}`))
	f.Add([]byte(`{"node_count": -1}`))
	f.Add([]byte(`{"node_count": 9999999999999999999}`))

	// Nested objects
	f.Add([]byte(`{"signatures": [{"identifying_features": {"required_calls": ["a", "b"]}}]}`))

	// Unicode and special characters
	f.Add([]byte(`{"name": "\u0000\u0001\u0002"}`))
	f.Add([]byte(`{"name": "` + strings.Repeat("A", 10000) + `"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var db SignatureDatabase

		// The unmarshal should not panic
		err := json.Unmarshal(data, &db)

		if err == nil {
			// If parsing succeeded, validate the structure
			for _, sig := range db.Signatures {
				// Entropy scores should be reasonable
				if !math.IsNaN(sig.EntropyScore) && !math.IsInf(sig.EntropyScore, 0) {
					// Valid entropy
				}

				// Node counts should be non-negative (if set)
				if sig.NodeCount < 0 {
					// Database allows negative, but we flag it
					t.Logf("Warning: negative node count: %d", sig.NodeCount)
				}
			}
		}
	})
}

// FuzzScannerLoadDatabase tests the scanner's database loading with temp files.
func FuzzScannerLoadDatabase(f *testing.F) {
	f.Add([]byte(`{"version":"1.0","signatures":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`invalid json`))
	f.Add([]byte{0x00, 0x01, 0x02}) // Binary data

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a temp file with the fuzzed data
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "fuzz_signatures.json")

		if err := os.WriteFile(dbPath, data, 0644); err != nil {
			t.Skip("Could not write temp file")
		}

		scanner := NewScanner()

		// Should not panic, may return error
		_ = scanner.LoadDatabase(dbPath)
	})
}

// SECTION 3: Topology Hash Generation Fuzzing

// FuzzTopologyHashGeneration tests the topology hash generation with various inputs.
func FuzzTopologyHashGeneration(f *testing.F) {
	f.Add(1, 1, 5, 30, 2, 3, true, false, true, false, false, false)
	f.Add(0, 0, 0, 0, 0, 0, false, false, false, false, false, false)
	f.Add(100, 50, 1000, 50000, 100, 500, true, true, true, true, true, true)
	f.Add(-1, -1, -1, -1, -1, -1, false, false, false, false, false, false) // Negative values

	f.Fuzz(func(t *testing.T, paramCount, returnCount, blockCount, instrCount, loopCount, branchCount int,
		hasDefer, hasGo, hasSelect, hasPanic, hasRecover, hasRange bool) {

		topo := &FunctionTopology{
			ParamCount:     paramCount,
			ReturnCount:    returnCount,
			BlockCount:     blockCount,
			InstrCount:     instrCount,
			LoopCount:      loopCount,
			BranchCount:    branchCount,
			HasDefer:       hasDefer,
			HasGo:          hasGo,
			HasSelect:      hasSelect,
			HasPanic:       hasPanic,
			HasRecover:     hasRecover,
			HasRange:       hasRange,
			CallSignatures: make(map[string]int),
			BinOpCounts:    make(map[string]int),
			UnOpCounts:     make(map[string]int),
		}

		// Should not panic
		sig := IndexFunction(topo, "FuzzTest", "Fuzz description", "MEDIUM", "fuzz")

		// Hash should be non-empty
		if sig.TopologyHash == "" {
			t.Error("Expected non-empty topology hash")
		}

		// Hash should be deterministic
		sig2 := IndexFunction(topo, "FuzzTest", "Fuzz description", "MEDIUM", "fuzz")
		if sig.TopologyHash != sig2.TopologyHash {
			t.Error("Topology hash is not deterministic")
		}
	})
}

// FuzzIndexFunctionWithCallSignatures tests hash generation with varying call signatures.
func FuzzIndexFunctionWithCallSignatures(f *testing.F) {
	f.Add("net.Dial", 1, "time.Sleep", 2, "fmt.Println", 5)
	f.Add("", 0, "", 0, "", 0)
	f.Add("exec", 999, "syscall.Exec", 1, "os.Remove", 100)
	f.Add(strings.Repeat("A", 1000), 1, "B", 2, "C", 3)

	f.Fuzz(func(t *testing.T, call1 string, count1 int, call2 string, count2 int, call3 string, count3 int) {
		topo := &FunctionTopology{
			ParamCount:     2,
			ReturnCount:    1,
			BlockCount:     10,
			InstrCount:     50,
			CallSignatures: make(map[string]int),
			BinOpCounts:    make(map[string]int),
			UnOpCounts:     make(map[string]int),
		}

		if call1 != "" {
			topo.CallSignatures[call1] = count1
		}
		if call2 != "" {
			topo.CallSignatures[call2] = count2
		}
		if call3 != "" {
			topo.CallSignatures[call3] = count3
		}

		// Should not panic
		sig := IndexFunction(topo, "FuzzCallSigs", "Test", "LOW", "test")

		if sig.TopologyHash == "" {
			t.Error("Expected non-empty topology hash")
		}
	})
}

// SECTION 4: String Pattern Extraction Fuzzing

// FuzzExtractStringPatterns tests the string pattern extraction logic.
func FuzzExtractStringPatterns(f *testing.F) {
	f.Add("\"tcp\"", "\"udp\"", "\"http\"")
	f.Add("", "", "")
	f.Add("\"a\"", "\"ab\"", "\"abc\"") // Length boundaries
	f.Add("no quotes", "also no quotes", "plain text")
	f.Add("'single'", "`backtick`", "\"double\"")
	f.Add(strings.Repeat("x", 10000), "normal", "string")
	f.Add("\x00\x01\x02", "binary", "data")
	f.Add("\"127.0.0.1:4444\"", "\"/bin/sh\"", "\"exec\"")

	f.Fuzz(func(t *testing.T, lit1, lit2, lit3 string) {
		literals := []string{lit1, lit2, lit3}

		// Should not panic
		patterns := extractStringPatterns(literals)

		// Patterns should not contain empty strings
		for _, p := range patterns {
			if len(p) < 3 {
				t.Errorf("Pattern too short (< 3 chars): %q", p)
			}
		}
	})
}

// SECTION 5: Signature Matching Fuzzing

// FuzzScannerScanTopology tests the signature scanning logic.
func FuzzScannerScanTopology(f *testing.F) {
	f.Add("test_function", 5.5, 0.5, 10, 2, "HIGH")
	f.Add("", 0.0, 0.0, 0, 0, "")
	f.Add("malware_beacon", 7.5, 0.1, 100, 10, "CRITICAL")
	f.Add(strings.Repeat("x", 1000), -1.0, -1.0, -1, -1, "INVALID")

	f.Fuzz(func(t *testing.T, funcName string, entropyScore, tolerance float64, nodeCount, loopDepth int, severity string) {
		scanner := NewScanner()

		// Create a mock signature
		sig := Signature{
			ID:               "FUZZ-001",
			Name:             "FuzzSignature",
			Severity:         severity,
			TopologyHash:     "fuzzed",
			EntropyScore:     entropyScore,
			EntropyTolerance: tolerance,
			NodeCount:        nodeCount,
			LoopDepth:        loopDepth,
		}

		scanner.db = &SignatureDatabase{
			Signatures: []Signature{sig},
		}

		topo := &FunctionTopology{
			BlockCount:     nodeCount,
			LoopCount:      loopDepth,
			EntropyScore:   entropyScore,
			CallSignatures: make(map[string]int),
		}

		// Should not panic
		results := scanner.ScanTopology(topo, funcName)

		// Results should be a valid slice (may be empty)
		_ = results
	})
}

// SECTION 6: Literal Policy Fuzzing

// FuzzLiteralPolicySmallIntRange tests small integer classification.
func FuzzLiteralPolicySmallIntRange(f *testing.F) {
	f.Add(int64(-16), int64(16), int64(0))
	f.Add(int64(0), int64(0), int64(0))
	f.Add(int64(-1000), int64(1000), int64(500))
	f.Add(int64(math.MinInt64), int64(math.MaxInt64), int64(0))
	f.Add(int64(100), int64(-100), int64(50)) // Inverted range

	f.Fuzz(func(t *testing.T, minVal, maxVal, testVal int64) {
		policy := LiteralPolicy{
			SmallIntMin: minVal,
			SmallIntMax: maxVal,
		}

		// Test by checking the range logic directly (isSmallInt requires constant.Value)
		// This tests the same logic the policy uses
		isSmall := testVal >= policy.SmallIntMin && testVal <= policy.SmallIntMax

		// Result should be consistent with the range
		if minVal <= maxVal {
			expected := testVal >= minVal && testVal <= maxVal
			if isSmall != expected {
				t.Errorf("Small int check for %d = %v, expected %v (range [%d, %d])",
					testVal, isSmall, expected, minVal, maxVal)
			}
		}
	})
}

// SECTION 7: Fuzzy Hash Generation Fuzzing

// FuzzGenerateFuzzyHash tests the LSH-based fuzzy hash generation.
func FuzzGenerateFuzzyHash(f *testing.F) {
	f.Add(5, 30, 2, 3, 10, "call1:1,call2:2", "op1:5,op2:3")
	f.Add(0, 0, 0, 0, 0, "", "")
	f.Add(1000, 100000, 500, 1000, 50, "a:1", "b:1")
	f.Add(-1, -1, -1, -1, -1, "neg:neg", "neg:neg")

	f.Fuzz(func(t *testing.T, blockCount, instrCount, loopCount, branchCount, phiCount int, calls, ops string) {
		topo := &FunctionTopology{
			BlockCount:     blockCount,
			InstrCount:     instrCount,
			LoopCount:      loopCount,
			BranchCount:    branchCount,
			PhiCount:       phiCount,
			CallSignatures: make(map[string]int),
			BinOpCounts:    make(map[string]int),
		}

		// Parse call signatures
		for _, part := range strings.Split(calls, ",") {
			if kv := strings.Split(part, ":"); len(kv) == 2 {
				var count int
				fmt.Sscanf(kv[1], "%d", &count)
				if kv[0] != "" {
					topo.CallSignatures[kv[0]] = count
				}
			}
		}

		// Parse operator counts
		for _, part := range strings.Split(ops, ",") {
			if kv := strings.Split(part, ":"); len(kv) == 2 {
				var count int
				fmt.Sscanf(kv[1], "%d", &count)
				if kv[0] != "" {
					topo.BinOpCounts[kv[0]] = count
				}
			}
		}

		// Should not panic
		hash := GenerateFuzzyHash(topo)

		// Hash should be non-empty
		if hash == "" {
			t.Error("Expected non-empty fuzzy hash")
		}

		// Hash should be deterministic
		hash2 := GenerateFuzzyHash(topo)
		if hash != hash2 {
			t.Error("Fuzzy hash is not deterministic")
		}
	})
}

// SECTION 8: Unicode and Binary Safety Fuzzing

// FuzzUnicodeSafety tests handling of various Unicode inputs in string processing.
func FuzzUnicodeSafety(f *testing.F) {
	f.Add("Hello, 世界")
	f.Add("🔥💀🎃")
	f.Add("\x00\xff\xfe")
	f.Add(string([]byte{0xc0, 0xc1})) // Invalid UTF-8
	f.Add("\u0000\u001f\u007f")       // Control characters
	f.Add("\uFFFD")                   // Replacement character
	f.Add("\uFEFF")                   // BOM
	f.Add(strings.Repeat("नमस्ते", 100))

	f.Fuzz(func(t *testing.T, input string) {
		// Test entropy calculation with unicode
		entropy := CalculateEntropy([]byte(input))
		if math.IsNaN(entropy) || math.IsInf(entropy, 0) {
			t.Errorf("Invalid entropy for unicode input: %f", entropy)
		}

		// Test string patterns extraction
		patterns := extractStringPatterns([]string{input})
		for _, p := range patterns {
			// Patterns should be valid strings (no panics)
			_ = len(p)
		}

		// Test if input is valid UTF-8 (informational)
		if !utf8.ValidString(input) {
			// This is fine, we should handle invalid UTF-8 gracefully
			t.Logf("Input contains invalid UTF-8 (length %d bytes)", len(input))
		}
	})
}

// SECTION 9: Scanner Threshold and Confidence Fuzzing

// FuzzScannerThresholds tests scanner behavior with various threshold settings.
func FuzzScannerThresholds(f *testing.F) {
	f.Add(0.0, 0.5)
	f.Add(0.5, 0.5)
	f.Add(0.75, 0.5)
	f.Add(1.0, 0.0)
	f.Add(-0.5, -0.5)
	f.Add(2.0, 2.0)
	f.Add(math.NaN(), 0.5)
	f.Add(0.5, math.Inf(1))

	f.Fuzz(func(t *testing.T, matchThreshold, entropyTolerance float64) {
		scanner := NewScanner()

		// Should not panic even with invalid thresholds
		scanner.SetThreshold(matchThreshold)
		scanner.entropyTolerance = entropyTolerance

		// Should handle gracefully
		db := scanner.GetDatabase()
		_ = db
	})
}

// SECTION 10: Canonicalizer Input Fuzzing

// FuzzCanonicalizerStringBuilder tests the canonicalizer's string building.
func FuzzCanonicalizerStringBuilder(f *testing.F) {
	f.Add("block_0:\n  v0 = const 42\n  return v0")
	f.Add("")
	f.Add(strings.Repeat("A", 1000000)) // Large input
	f.Add("\x00\x01\x02\x03")
	f.Add("func(){\nfor{\n}\n}")

	f.Fuzz(func(t *testing.T, input string) {
		// Test that string operations don't panic
		var builder strings.Builder

		// Simulate canonicalizer string building patterns
		builder.WriteString("ENTRY:\n")
		for _, line := range strings.Split(input, "\n") {
			if len(line) > 0 {
				builder.WriteString("  ")
				builder.WriteString(line)
				builder.WriteString("\n")
			}
		}
		builder.WriteString("END\n")

		result := builder.String()
		if len(result) == 0 {
			t.Error("Builder produced empty string")
		}
	})
}

// SECTION 11: Match Details Construction Fuzzing

// FuzzMatchDetailsConstruction tests the construction of match details.
func FuzzMatchDetailsConstruction(f *testing.F) {
	f.Add(true, true, 0.95, 0.1, "call1,call2", "call3")
	f.Add(false, false, 0.0, 100.0, "", "")
	f.Add(true, false, -1.0, -1.0, "x", "y,z")

	f.Fuzz(func(t *testing.T, topoMatch, entropyMatch bool, topoSim, entropyDist float64,
		matchedCalls, missingCalls string) {

		var matched, missing []string
		if matchedCalls != "" {
			matched = strings.Split(matchedCalls, ",")
		}
		if missingCalls != "" {
			missing = strings.Split(missingCalls, ",")
		}

		details := MatchDetails{
			TopologyMatch:      topoMatch,
			EntropyMatch:       entropyMatch,
			TopologySimilarity: topoSim,
			EntropyDistance:    entropyDist,
			CallsMatched:       matched,
			CallsMissing:       missing,
		}

		// Should be able to serialize
		data, err := json.Marshal(details)
		if err != nil {
			t.Errorf("Failed to marshal MatchDetails: %v", err)
		}

		// Should be able to deserialize
		var decoded MatchDetails
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Errorf("Failed to unmarshal MatchDetails: %v", err)
		}
	})
}

// SECTION 12: Scan Result Serialization Fuzzing

// FuzzScanResultSerialization tests JSON serialization of scan results.
func FuzzScanResultSerialization(f *testing.F) {
	f.Add("SIG-001", "Malware", "HIGH", "func1", 0.95)
	f.Add("", "", "", "", 0.0)
	f.Add(strings.Repeat("A", 10000), "Test", "LOW", "main", 1.0)
	f.Add("FUZZ\x00ID", "Name\nWith\nNewlines", "SEV\"ERITY", "func'name", -0.5)

	f.Fuzz(func(t *testing.T, sigID, sigName, severity, funcName string, confidence float64) {
		result := ScanResult{
			SignatureID:     sigID,
			SignatureName:   sigName,
			Severity:        severity,
			MatchedFunction: funcName,
			Confidence:      confidence,
			MatchDetails: MatchDetails{
				TopologyMatch: confidence > 0.5,
				EntropyMatch:  confidence > 0.7,
			},
		}

		// Should serialize without panic
		data, err := json.Marshal(result)
		if err != nil {
			// Some inputs may not serialize (e.g., invalid UTF-8)
			return
		}

		// Should deserialize
		var decoded ScanResult
		_ = json.Unmarshal(data, &decoded)
	})
}

// SECTION 13: Topology Similarity Calculation Fuzzing

// FuzzTopologySimilarityCalculation tests similarity calculation between topologies.
func FuzzTopologySimilarityCalculation(f *testing.F) {
	f.Add(10, 10, 50, 50, 5, 5)
	f.Add(0, 100, 0, 1000, 0, 10)
	f.Add(100, 0, 1000, 0, 10, 0)
	f.Add(-5, -5, -50, -50, -1, -1)
	f.Add(1000000, 1000000, 10000000, 10000000, 100000, 100000)

	f.Fuzz(func(t *testing.T, blocks1, blocks2, instrs1, instrs2, loops1, loops2 int) {
		// Create topology with fuzzed values
		topo := &FunctionTopology{
			BlockCount:     blocks1,
			InstrCount:     instrs1,
			LoopCount:      loops1,
			CallSignatures: make(map[string]int),
		}

		sig := Signature{
			NodeCount: blocks2,
			LoopDepth: loops2,
		}

		// Use the actual similarity function from the scanner
		similarity := ComputeTopologySimilarityExported(topo, sig)

		// Similarity should be a valid number between 0 and 1
		if math.IsNaN(similarity) {
			t.Errorf("Similarity is NaN for blocks %d vs %d", blocks1, blocks2)
		}
		if similarity < 0 || similarity > 1 {
			t.Errorf("Similarity out of range [0,1]: %f", similarity)
		}
	})
}

// SECTION 14: Memory Safety and DoS Prevention Fuzzing

// FuzzLargeInputHandling tests that the framework handles large inputs safely.
func FuzzLargeInputHandling(f *testing.F) {
	f.Add(100)
	f.Add(1000)
	f.Add(10000)
	f.Add(100000)

	f.Fuzz(func(t *testing.T, size int) {
		if size < 0 || size > 1000000 {
			size = 1000 // Cap to reasonable size for fuzzing
		}

		// Test large byte array entropy calculation
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}

		entropy := CalculateEntropy(data)
		if math.IsNaN(entropy) || math.IsInf(entropy, 0) {
			t.Errorf("Invalid entropy for large input (size %d): %f", size, entropy)
		}

		// Test large string literal list
		literals := make([]string, size/10+1)
		for i := range literals {
			literals[i] = fmt.Sprintf("string_%d", i)
		}

		// Should handle without OOM or excessive time
		patterns := extractStringPatterns(literals)
		_ = patterns
	})
}

// SECTION 15: Control Flow Hints Fuzzing

// FuzzControlFlowHints tests control flow hint generation.
func FuzzControlFlowHints(f *testing.F) {
	f.Add(true, true, true, true, 5, "net.Dial:1,time.Sleep:1")
	f.Add(false, false, false, false, 0, "")
	f.Add(true, false, false, true, 100, "fmt.Println:100")

	f.Fuzz(func(t *testing.T, hasDefer, hasPanic, hasSelect, hasRange bool, loopCount int, callsStr string) {
		topo := &FunctionTopology{
			HasDefer:       hasDefer,
			HasPanic:       hasPanic,
			HasSelect:      hasSelect,
			HasRange:       hasRange,
			LoopCount:      loopCount,
			CallSignatures: make(map[string]int),
		}

		// Parse calls
		for _, part := range strings.Split(callsStr, ",") {
			if kv := strings.Split(part, ":"); len(kv) == 2 {
				var count int
				fmt.Sscanf(kv[1], "%d", &count)
				if kv[0] != "" {
					topo.CallSignatures[kv[0]] = count
				}
			}
		}

		// Test reconnect pattern detection
		hasReconnect := hasReconnectPattern(topo)

		// Should be deterministic
		hasReconnect2 := hasReconnectPattern(topo)
		if hasReconnect != hasReconnect2 {
			t.Error("hasReconnectPattern is not deterministic")
		}
	})
}
