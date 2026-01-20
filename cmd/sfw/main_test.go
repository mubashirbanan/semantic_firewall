// -- ./cmd/sfw/main_test.go --
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -- Unit Tests --

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// BUG FIX VERIFICATION: Test for exact "_test.go" filename
		// Previously, isTestFile("_test.go") returned false due to > 8 instead of >= 8
		{
			name:     "exact _test.go filename",
			path:     "_test.go",
			expected: true,
		},
		{
			name:     "exact _test.go with directory",
			path:     "/some/path/_test.go",
			expected: true,
		},
		// Standard test file cases
		{
			name:     "standard test file",
			path:     "foo_test.go",
			expected: true,
		},
		{
			name:     "test file with path",
			path:     "/home/user/project/handler_test.go",
			expected: true,
		},
		{
			name:     "longer test file name",
			path:     "some_long_name_test.go",
			expected: true,
		},
		// Non-test file cases
		{
			name:     "regular go file",
			path:     "main.go",
			expected: false,
		},
		{
			name:     "file with test in name but not suffix",
			path:     "test_utils.go",
			expected: false,
		},
		{
			name:     "file ending in test without underscore",
			path:     "mytest.go",
			expected: false,
		},
		{
			name:     "short filename",
			path:     "a.go",
			expected: false,
		},
		{
			name:     "exactly 7 characters (less than _test.go)",
			path:     "ab_test",
			expected: false,
		},
		{
			name:     "file with _test.go in middle",
			path:     "_test.go.bak",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTestFile(tt.path)
			if result != tt.expected {
				t.Errorf("isTestFile(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestShortFunctionName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"testpkg.main", "main"},
		{"testpkg.init", "init"},
		{"testpkg.(*Type).Method", "(*Type).Method"},
		{"pkg.Func", "Func"},
		{"a.b.c", "b.c"}, // Takes first dot outside parens (legacy behavior)
		{"NoDot", "NoDot"},
		// New cases for full module paths
		{"github.com/BlackVectorOps/semantic_firewall/v2/samples/clean.StartBeacon", "StartBeacon"},
		{"github.com/BlackVectorOps/semantic_firewall/v2/samples/dirty.z", "z"},
		{"github.com/foo/bar.(*Type).Method", "(*Type).Method"},
		{"github.com/foo/bar.init", "init"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := shortFunctionName(tt.input)
			if result != tt.expected {
				t.Errorf("shortFunctionName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCompareFunctions_Preserved(t *testing.T) {
	// Test the compareFunctions helper with matching fingerprints
	src := `package main
func identity(x int) int {
return x
}
`
	dir, err := os.MkdirTemp("", "sfw-compare-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "test.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	results, err := loadAndFingerprint(path)
	if err != nil {
		t.Fatalf("Failed to load file: %v", err)
	}

	// Find identity function
	var identityResult *struct {
		FunctionName string
		Fingerprint  string
	}
	for _, r := range results {
		if shortFunctionName(r.FunctionName) == "identity" {
			identityResult = &struct {
				FunctionName string
				Fingerprint  string
			}{r.FunctionName, r.Fingerprint}
			break
		}
	}

	if identityResult == nil {
		t.Fatal("Could not find identity function")
	}

	// Comparing same result should show preserved
	diff := compareFunctions("identity", results[0], results[0])
	if diff.Status != "preserved" {
		t.Errorf("Same function should be preserved, got: %s", diff.Status)
	}
	if !diff.FingerprintMatch {
		t.Error("FingerprintMatch should be true for identical functions")
	}
}

// -- CLI TEST HELPERS --

// captureOutput hijacks os.Stdout to capture the JSON output from the CLI commands.
// This is necessary because runCheck, runIndex, etc., hardcode output to stdout.
func captureOutput(f func() error) (string, error) {
	// Save original stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run the function
	err := f()

	// Restore stdout and close the pipe
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), err
}

// createTempSource writes a Go file to a temp directory for testing.
func createTempSource(t *testing.T, filename, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp source: %v", err)
	}
	return path
}

// -- CLI COMMAND TESTS --

func TestRunCheck_Basic(t *testing.T) {
	// 1. Setup a valid Go file
	// Fixed: Added backticks for string literal
	src := `package main 
    func main() { println("fingerprint me") }`
	path := createTempSource(t, "main.go", src)

	// 2. Run 'sfw check' logic
	output, err := captureOutput(func() error {
		// Strict=false, Scan=false, DB=""
		return runCheck(path, false, false, "")
	})

	if err != nil {
		t.Fatalf("runCheck failed: %v", err)
	}

	// 3. Verify JSON output
	var result FileOutput
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("Failed to parse check output: %v\nRaw: %s", err, output)
	}

	if result.File == "" {
		t.Error("Expected filename in output")
	}
	if len(result.Functions) == 0 {
		t.Error("Expected at least one function fingerprint")
	} else {
		foundMain := false
		for _, fn := range result.Functions {
			if strings.Contains(fn.Function, "main") {
				foundMain = true
				break
			}
		}
		if !foundMain {
			// Dump found names for debugging
			var names []string
			for _, fn := range result.Functions {
				names = append(names, fn.Function)
			}
			t.Errorf("Expected function 'main.main', found: %v", names)
		}
	}
}

func TestWorkflow_PebbleDB(t *testing.T) {
	// This tests the full lifecycle: Index -> Scan -> Stats using the Pebble backend
	// This covers the logic in main.go where it checks !isJSON(dbPath)

	// 1. Setup Data
	malwareSrc := `package main
func payload() {
    // Specific topology: Panic + No args
    panic("malware")
}`
	malwarePath := createTempSource(t, "malware.go", malwareSrc)

	targetSrc := `package main
func target() {
    panic("infected")
}`
	targetPath := createTempSource(t, "target.go", targetSrc)

	// 2. Define DB Path (No extension defaults to Pebble in your logic)
	dbPath := filepath.Join(t.TempDir(), "sigs-pebble")

	// -- STEP A: INDEX --
	t.Run("Index", func(t *testing.T) {
		output, err := captureOutput(func() error {
			return runIndex(malwarePath, "Exploit.Panic", "HIGH", "exploit", dbPath)
		})
		if err != nil {
			t.Fatalf("runIndex failed: %v", err)
		}
		// Expect 2 functions because 'init' is often generated by ssa for packages
		if !strings.Contains(output, "Indexed 2 functions") {
			t.Errorf("Unexpected index output: %s", output)
		}
	})

	// -- STEP B: SCAN --
	t.Run("Scan", func(t *testing.T) {
		opts := ScanOptions{
			DBPath:    dbPath,
			Threshold: 0.6, // Loose threshold to ensure match on similar topology
			ExactOnly: false,
		}

		output, err := captureOutput(func() error {
			return runScan(targetPath, opts)
		})
		if err != nil {
			t.Fatalf("runScan failed: %v", err)
		}

		var res ScanOutput
		if err := json.Unmarshal([]byte(output), &res); err != nil {
			t.Fatalf("Failed to parse scan output: %v", err)
		}

		// Expect 2 Alerts because init is similar to init, and target is similar to payload
		if res.Summary.HighAlerts != 2 {
			t.Errorf("Expected 2 High Alert, got %d. Alerts: %v", res.Summary.HighAlerts, res.Alerts)
		}
		if res.Backend != "pebbledb" {
			t.Errorf("Expected backend 'pebbledb', got '%s'", res.Backend)
		}
	})

	// -- STEP C: STATS --
	t.Run("Stats", func(t *testing.T) {
		output, err := captureOutput(func() error {
			return runStats(dbPath)
		})
		if err != nil {
			t.Fatalf("runStats failed: %v", err)
		}
		if !strings.Contains(output, `"signature_count": 2`) {
			t.Errorf("Stats count incorrect. Output: %s", output)
		}
	})
}

func TestWorkflow_JSONDB(t *testing.T) {
	// Tests the logic branch for .json files

	src := `package main
func bad() { print("evil") }`
	path := createTempSource(t, "bad.go", src)

	// Explicit .json extension triggers the JSON path in main.go
	dbPath := filepath.Join(t.TempDir(), "sigs.json")

	// 1. Index
	_, err := captureOutput(func() error {
		return runIndex(path, "Bad.Print", "LOW", "test", dbPath)
	})
	if err != nil {
		t.Fatalf("runIndex (JSON) failed: %v", err)
	}

	// 2. Scan
	opts := ScanOptions{DBPath: dbPath, Threshold: 0.5}
	output, err := captureOutput(func() error {
		return runScan(path, opts)
	})

	// Verify backend reporting
	var res ScanOutput
	json.Unmarshal([]byte(output), &res)
	if res.Backend != "json" {
		t.Errorf("Expected backend 'json', got '%s'", res.Backend)
	}
}

func TestRunMigrate(t *testing.T) {
	// 1. Create a dummy legacy JSON database
	jsonDir := t.TempDir()
	jsonDB := filepath.Join(jsonDir, "legacy.json")
	// Fixed: Added backticks for string literal
	dummyJSON := `{ "version": "1.0", "signatures": [ { "id": "TEST-001", "name": "Legacy_Sig", "description": "Old signature", "topology_hash": "dummyhash",  "entropy_score": 5.0, "identifying_features": {} } ] }`
	if err := os.WriteFile(jsonDB, []byte(dummyJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Define destination Pebble DB
	pebbleDB := filepath.Join(t.TempDir(), "new-pebble-db")

	// 3. Run Migrate
	output, err := captureOutput(func() error {
		return runMigrate(jsonDB, pebbleDB)
	})
	if err != nil {
		t.Fatalf("runMigrate failed: %v", err)
	}

	// 4. Verify Output
	if !strings.Contains(output, "Successfully migrated 1 signatures") {
		t.Errorf("Migration output mismatch: %s", output)
	}
}

func TestLevenshtein(t *testing.T) {
	// Unit test for the typo suggestion logic used in main() command routing
	tests := []struct {
		s1, s2 string
		want   int
	}{
		{"audit", "audit", 0},
		{"adit", "audit", 1},
		{"auditt", "audit", 1},
		// check -> chuck (sub e->u) = 1; chuck -> chunk (ins n) = 2. Distance is 2.
		{"check", "chunk", 2},
		{"", "abc", 3},
	}

	for _, tt := range tests {
		got := levenshtein(tt.s1, tt.s2)
		if got != tt.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.s1, tt.s2, got, tt.want)
		}
	}
}

func TestSuggestCommand(t *testing.T) {
	// Verifies the "Did you mean...?" logic
	if got := suggestCommand("chk"); got != "check" {
		t.Errorf("Expected suggestion 'check' for 'chk', got %q", got)
	}
	if got := suggestCommand("adit"); got != "audit" {
		t.Errorf("Expected suggestion 'audit' for 'adit', got %q", got)
	}
	if got := suggestCommand("xyz"); got != "" {
		t.Errorf("Expected no suggestion for 'xyz', got %q", got)
	}
}
