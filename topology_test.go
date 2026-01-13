package semanticfw

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractTopology_BasicFunction(t *testing.T) {
	src := `
package main

func simpleLoop() {
	for i := 0; i < 10; i++ {
		println(i)
	}
}
`
	tempDir, cleanup := setupTestEnv(t, "topo-basic-")
	defer cleanup()

	tempFile := filepath.Join(tempDir, "test.go")
	if err := os.WriteFile(tempFile, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(tempFile, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	var topo *FunctionTopology
	for _, r := range results {
		if fn := r.GetSSAFunction(); fn != nil {
			name := shortFuncName(r.FunctionName)
			if name == "simpleLoop" {
				topo = ExtractTopology(fn)
				break
			}
		}
	}

	if topo == nil {
		t.Fatal("Could not extract topology for simpleLoop")
	}

	if topo.LoopCount != 1 {
		t.Errorf("Expected 1 loop, got %d", topo.LoopCount)
	}

	if topo.ParamCount != 0 {
		t.Errorf("Expected 0 params, got %d", topo.ParamCount)
	}
}

func TestTopologySimilarity_IdenticalFunctions(t *testing.T) {
	src := `
package main

import "fmt"

func funcA() {
	for i := 0; i < 10; i++ {
		if i > 5 {
			fmt.Println(i)
		}
	}
}

func funcB() {
	for j := 0; j < 10; j++ {
		if j > 5 {
			fmt.Println(j)
		}
	}
}
`
	tempDir, cleanup := setupTestEnv(t, "topo-identical-")
	defer cleanup()

	tempFile := filepath.Join(tempDir, "test.go")
	if err := os.WriteFile(tempFile, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(tempFile, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	var topoA, topoB *FunctionTopology
	for _, r := range results {
		fn := r.GetSSAFunction()
		if fn == nil {
			continue
		}
		name := shortFuncName(r.FunctionName)
		switch name {
		case "funcA":
			topoA = ExtractTopology(fn)
		case "funcB":
			topoB = ExtractTopology(fn)
		}
	}

	if topoA == nil || topoB == nil {
		t.Fatal("Could not extract topologies")
	}

	sim := TopologySimilarity(topoA, topoB)
	if sim < 0.9 {
		t.Errorf("Expected high similarity for structurally identical functions, got %.2f", sim)
	}
}

func TestTopologySimilarity_DifferentFunctions(t *testing.T) {
	src := `
package main

import "fmt"
import "net"

func loopFunc() {
	for i := 0; i < 10; i++ {
		fmt.Println(i)
	}
}

func networkFunc() {
	conn, _ := net.Dial("tcp", "localhost:80")
	if conn != nil {
		conn.Close()
	}
}
`
	tempDir, cleanup := setupTestEnv(t, "topo-diff-")
	defer cleanup()

	tempFile := filepath.Join(tempDir, "test.go")
	if err := os.WriteFile(tempFile, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(tempFile, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	var topoLoop, topoNet *FunctionTopology
	for _, r := range results {
		fn := r.GetSSAFunction()
		if fn == nil {
			continue
		}
		name := shortFuncName(r.FunctionName)
		switch name {
		case "loopFunc":
			topoLoop = ExtractTopology(fn)
		case "networkFunc":
			topoNet = ExtractTopology(fn)
		}
	}

	if topoLoop == nil || topoNet == nil {
		t.Fatal("Could not extract topologies")
	}

	sim := TopologySimilarity(topoLoop, topoNet)
	if sim > 0.6 {
		t.Errorf("Expected low similarity for structurally different functions, got %.2f", sim)
	}
}

func TestMatchFunctionsByTopology_RenamedFunctions(t *testing.T) {
	oldSrc := `
package main

import "fmt"

func StartBeacon() {
	for {
		fmt.Println("beacon")
	}
}

func HandleConnection() {
	defer func() { recover() }()
	fmt.Println("handle")
}
`
	newSrc := `
package main

import "fmt"

func z() {
	for {
		fmt.Println("beacon")
	}
}

func y() {
	defer func() { recover() }()
	fmt.Println("handle")
}
`
	// Create separate directories for old and new
	oldDir, oldCleanup := setupTestEnv(t, "topo-old-")
	defer oldCleanup()
	newDir, newCleanup := setupTestEnv(t, "topo-new-")
	defer newCleanup()

	oldFile := filepath.Join(oldDir, "old.go")
	if err := os.WriteFile(oldFile, []byte(oldSrc), 0644); err != nil {
		t.Fatalf("Failed to write old file: %v", err)
	}

	newFile := filepath.Join(newDir, "new.go")
	if err := os.WriteFile(newFile, []byte(newSrc), 0644); err != nil {
		t.Fatalf("Failed to write new file: %v", err)
	}

	oldResults, err := FingerprintSource(oldFile, oldSrc, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource old failed: %v", err)
	}

	newResults, err := FingerprintSource(newFile, newSrc, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource new failed: %v", err)
	}

	matched, added, removed := MatchFunctionsByTopology(oldResults, newResults, 0.6)

	// Log what we got for debugging
	t.Logf("Matched: %d, Added: %d, Removed: %d", len(matched), len(added), len(removed))
	for _, m := range matched {
		t.Logf("Match: %s -> %s (byName=%v, sim=%.2f)",
			shortFuncName(m.OldResult.FunctionName),
			shortFuncName(m.NewResult.FunctionName),
			m.ByName, m.Similarity)
	}

	// Should have matched StartBeacon->z and HandleConnection->y
	renamedCount := 0
	for _, m := range matched {
		if !m.ByName {
			renamedCount++
		}
	}

	if renamedCount < 2 {
		t.Errorf("Expected at least 2 renamed function matches, got %d", renamedCount)
	}

	if len(added) != 0 {
		t.Errorf("Expected 0 added functions, got %d", len(added))
	}

	if len(removed) != 0 {
		t.Errorf("Expected 0 removed functions, got %d", len(removed))
	}
}

func TestMatchFunctionsByTopology_TrulyNewFunction(t *testing.T) {
	oldSrc := `
package main

func existing() {
	println("hello")
}
`
	newSrc := `
package main

func existing() {
	println("hello")
}

func brandNew() {
	for i := 0; i < 100; i++ {
		println(i)
	}
}
`
	// Create separate directories for old and new
	oldDir, oldCleanup := setupTestEnv(t, "topo-old2-")
	defer oldCleanup()
	newDir, newCleanup := setupTestEnv(t, "topo-new2-")
	defer newCleanup()

	oldFile := filepath.Join(oldDir, "old.go")
	if err := os.WriteFile(oldFile, []byte(oldSrc), 0644); err != nil {
		t.Fatalf("Failed to write old file: %v", err)
	}

	newFile := filepath.Join(newDir, "new.go")
	if err := os.WriteFile(newFile, []byte(newSrc), 0644); err != nil {
		t.Fatalf("Failed to write new file: %v", err)
	}

	oldResults, err := FingerprintSource(oldFile, oldSrc, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource old failed: %v", err)
	}

	newResults, err := FingerprintSource(newFile, newSrc, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource new failed: %v", err)
	}

	matched, added, removed := MatchFunctionsByTopology(oldResults, newResults, 0.6)

	// existing should be matched by name
	foundExisting := false
	for _, m := range matched {
		name := shortFuncName(m.OldResult.FunctionName)
		if name == "existing" && m.ByName {
			foundExisting = true
		}
	}

	if !foundExisting {
		t.Error("Expected 'existing' to be matched by name")
	}

	// brandNew should be in added (no match in old)
	foundAdded := false
	for _, a := range added {
		name := shortFuncName(a.FunctionName)
		if name == "brandNew" {
			foundAdded = true
		}
	}

	if !foundAdded {
		t.Error("Expected 'brandNew' to be in added functions")
	}

	if len(removed) != 0 {
		t.Errorf("Expected 0 removed functions, got %d", len(removed))
	}
}

func TestTopologyFingerprint(t *testing.T) {
	src := `
package main

import "fmt"
import "net"

func beacon() {
	for {
		conn, _ := net.Dial("tcp", "localhost:80")
		if conn != nil {
			fmt.Println("connected")
		}
	}
}
`
	tempDir, cleanup := setupTestEnv(t, "topo-fp-")
	defer cleanup()

	tempFile := filepath.Join(tempDir, "test.go")
	if err := os.WriteFile(tempFile, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(tempFile, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	for _, r := range results {
		fn := r.GetSSAFunction()
		if fn == nil {
			continue
		}
		name := shortFuncName(r.FunctionName)
		if name == "beacon" {
			topo := ExtractTopology(fn)
			fp := TopologyFingerprint(topo)

			// Should contain loop count, branch count, instruction count and calls
			if fp == "" || fp == "nil" {
				t.Error("Expected non-empty topology fingerprint")
			}

			// Log for debugging
			t.Logf("Topology fingerprint: %s", fp)

			if topo.LoopCount != 1 {
				t.Errorf("Expected 1 loop, got %d", topo.LoopCount)
			}
			if topo.BranchCount != 1 {
				t.Errorf("Expected 1 branch, got %d", topo.BranchCount)
			}
			if _, ok := topo.CallSignatures["net.Dial"]; !ok {
				t.Error("Expected net.Dial in call signatures")
			}
			return
		}
	}
	t.Error("beacon function not found")
}
