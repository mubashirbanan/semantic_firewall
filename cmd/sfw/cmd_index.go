// cmd_index.go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

func runIndex(target, name, severity, category, dbPath string) error {
	results, err := loadAndFingerprint(target)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return fmt.Errorf("no functions found in %s", target)
	}

	var indexed []semanticfw.Signature
	var totalSigs int

	if !isJSON(dbPath) {
		indexed, totalSigs, err = runIndexPebble(target, results, name, severity, category, dbPath)
	} else {
		indexed, totalSigs, err = runIndexJSON(target, results, name, severity, category, dbPath)
	}
	if err != nil {
		return err
	}

	output := struct {
		Message   string                 `json:"message"`
		Indexed   []semanticfw.Signature `json:"indexed"`
		Database  string                 `json:"database"`
		TotalSigs int                    `json:"total_signatures"`
		Backend   string                 `json:"backend"`
	}{
		Message:   fmt.Sprintf("Indexed %d functions from %s", len(indexed), target),
		Indexed:   indexed,
		Database:  dbPath,
		TotalSigs: totalSigs,
		Backend:   map[bool]string{true: "json", false: "pebbledb"}[isJSON(dbPath)],
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runIndexPebble(target string, results []semanticfw.FingerprintResult, name, severity, category, dbPath string) ([]semanticfw.Signature, int, error) {
	scanner, err := semanticfw.NewPebbleScanner(dbPath, semanticfw.DefaultPebbleScannerOptions())
	if err != nil {
		return nil, 0, err
	}
	defer scanner.Close()

	// Handle error return
	existingCount, err := scanner.CountSignatures()
	if err != nil {
		return nil, 0, err
	}
	var sigs []semanticfw.Signature

	// Bounds check to prevent panic
	catShort := category
	if len(catShort) > 3 {
		catShort = catShort[:3]
	}

	for i, result := range results {
		fn := result.GetSSAFunction()
		if fn == nil {
			continue
		}
		topo := semanticfw.ExtractTopology(fn)
		if topo == nil {
			continue
		}

		funcName := shortFunctionName(result.FunctionName)
		sigName := fmt.Sprintf("%s_%s", name, funcName)
		desc := fmt.Sprintf("Function %s from %s", funcName, filepath.Base(target))

		sig := semanticfw.IndexFunction(topo, sigName, desc, severity, category)
		// Use Timestamp + Index to avoid ID collisions on re-index/delete
		sig.ID = fmt.Sprintf("SFW-%s-%d-%d", strings.ToUpper(catShort), time.Now().Unix(), existingCount+i+1)
		sig.Metadata = semanticfw.SignatureMetadata{
			Author:  "sfw-index",
			Created: time.Now().Format("2006-01-02"),
		}
		sigs = append(sigs, sig)
	}

	if err := scanner.AddSignatures(sigs); err != nil {
		return nil, 0, err
	}
	finalCount, _ := scanner.CountSignatures()
	return sigs, finalCount, nil
}

func runIndexJSON(target string, results []semanticfw.FingerprintResult, name, severity, category, dbPath string) ([]semanticfw.Signature, int, error) {
	scanner := semanticfw.NewScanner()
	if _, err := os.Stat(dbPath); err == nil {
		if err := scanner.LoadDatabase(dbPath); err != nil {
			return nil, 0, err
		}
	}

	// Bounds check
	catShort := category
	if len(catShort) > 3 {
		catShort = catShort[:3]
	}

	var indexed []semanticfw.Signature
	for _, result := range results {
		fn := result.GetSSAFunction()
		if fn == nil {
			continue
		}
		topo := semanticfw.ExtractTopology(fn)
		if topo == nil {
			continue
		}

		funcName := shortFunctionName(result.FunctionName)
		sigName := fmt.Sprintf("%s_%s", name, funcName)
		desc := fmt.Sprintf("Function %s from %s", funcName, filepath.Base(target))

		sig := semanticfw.IndexFunction(topo, sigName, desc, severity, category)
		sig.ID = fmt.Sprintf("SFW-%s-%d", strings.ToUpper(catShort), len(scanner.GetDatabase().Signatures)+len(indexed)+1)
		sig.Metadata = semanticfw.SignatureMetadata{
			Author:  "sfw-index",
			Created: time.Now().Format("2006-01-02"),
		}

		scanner.AddSignature(sig)
		indexed = append(indexed, sig)
	}

	if err := scanner.SaveDatabase(dbPath); err != nil {
		return nil, 0, err
	}
	return indexed, len(scanner.GetDatabase().Signatures), nil
}
