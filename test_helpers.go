package semanticfw

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SetupTestEnv creates an isolated test environment for packages loader.
// Exported for use in external test packages.
func SetupTestEnv(t *testing.T, dirPrefix string) (string, func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", dirPrefix)
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	// Create a minimal go.mod with go version for modern language features.
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte("module testmod\n\ngo 1.23\n"), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}
	cleanup := func() {
		os.RemoveAll(tempDir)
	}
	return tempDir, cleanup
}

// FindResult searches for a FingerprintResult by function name.
// It supports both exact matches and suffix matches (e.g., "functionName" matches "pkg.functionName").
// Exported for use in external test packages.
func FindResult(results []FingerprintResult, name string) *FingerprintResult {
	// First try exact match
	for i := range results {
		if results[i].FunctionName == name {
			return &results[i]
		}
	}
	// Then try suffix match for package-qualified names (e.g., "main" matches "testmod.main")
	for i := range results {
		// Match if the name is the suffix after the last "." for non-method functions
		// or matches with a potential package prefix
		funcName := results[i].FunctionName
		if strings.HasSuffix(funcName, "."+name) {
			return &results[i]
		}
		// Also handle cases like "(*Type).Method" where we just search for "Method"
		if strings.HasSuffix(funcName, name) && len(funcName) > len(name) {
			// Make sure we're at a word boundary
			prevChar := funcName[len(funcName)-len(name)-1]
			if prevChar == '.' || prevChar == ')' {
				return &results[i]
			}
		}
	}
	return nil
}

// GetFunctionNames extracts function names from results for easier verification.
// Exported for use in external test packages.
func GetFunctionNames(results []FingerprintResult) []string {
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.FunctionName
	}
	return names
}

// CheckIRPattern checks IR against a pattern using regex, abstracting register names.
// Exported for use in external test packages.
func CheckIRPattern(t *testing.T, ir string, pattern string) {
	// 1. Escape the input pattern so regex meta-characters (like [, ], (, )) are treated literally.
	escapedPattern := regexp.QuoteMeta(pattern)

	// 2. Replace the placeholder <vN> with the regex pattern for registers.
	// Regex pattern: (?:[vp]\d+|fv\d+) matches vN, pN, or fvN
	// We must match the escaped version of the placeholder (e.g., \<vN\>).
	placeholder := regexp.QuoteMeta("<vN>")
	regexPattern := strings.ReplaceAll(escapedPattern, placeholder, `(?:[vp]\d+|fv\d+)`)

	// 3. Replace <ANY> with a non-greedy wildcard match for any characters
	anyPlaceholder := regexp.QuoteMeta("<ANY>")
	regexPattern = strings.ReplaceAll(regexPattern, anyPlaceholder, `[^>]+`)

	match, err := regexp.MatchString(regexPattern, ir)
	if err != nil {
		t.Fatalf("Invalid regex pattern generated from: %s\nRegex: %s\nError: %v", pattern, regexPattern, err)
	}
	if !match {
		t.Errorf("Expected pattern not found in IR.\nPattern: %s\nRegex: %s\nActual IR:\n%s", pattern, regexPattern, ir)
	}
}

// ShortFuncName returns the short function name without package prefix.
// Exported for use in external test packages.
func ShortFuncName(fullName string) string {
	return shortFuncName(fullName)
}

// CompileAndGetFunction is a helper to compile source and get a named SSA function.
// Exported for use in external test packages.
func CompileAndGetFunction(t *testing.T, src, funcName string) *FingerprintResult {
	t.Helper()

	// Use SetupTestEnv to create a proper isolated directory
	tempDir, cleanup := SetupTestEnv(t, "compile-test-")
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
	for i := range results {
		if strings.HasSuffix(results[i].FunctionName, "."+funcName) || results[i].FunctionName == funcName {
			return &results[i]
		}
	}

	t.Logf("Available functions: %v", GetFunctionNames(results))
	return nil
}

// GenerateTopologyHashExported exports the generateTopologyHash function for testing.
func GenerateTopologyHashExported(topo *FunctionTopology) string {
	return generateTopologyHash(topo)
}

// ComputeTopologySimilarityExported exports the computeTopologySimilarity function for testing.
func ComputeTopologySimilarityExported(topo *FunctionTopology, sig Signature) float64 {
	return computeTopologySimilarity(topo, sig)
}

// MatchCallsExported exports the matchCalls function for testing.
func MatchCallsExported(topo *FunctionTopology, required []string) (score float64, matched, missing []string) {
	return matchCalls(topo, required)
}

// FormatEntropyKeyExported exports the formatEntropyKey function for testing.
func FormatEntropyKeyExported(entropy float64, id string) string {
	return formatEntropyKey(entropy, id)
}
