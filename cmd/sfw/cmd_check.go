// cmd_check.go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

// -- CHECK COMMAND --

// Processes one or more files to generate semantic fingerprints and optionally scan them.
func runCheck(target string, strictMode bool, enableScan bool, dbPath string) error {
	// Recursive file collection
	files, err := collectFiles(target)
	if err != nil {
		return fmt.Errorf("collect files failed: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no Go files found in %s", target)
	}

	var scanner *semanticfw.PebbleScanner
	if enableScan {
		if !isJSON(dbPath) {
			opts := semanticfw.DefaultPebbleScannerOptions()
			opts.ReadOnly = true
			scanner, err = semanticfw.NewPebbleScanner(dbPath, opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not open signature database: %v\n", err)
			} else {
				defer scanner.Close()
			}
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	for _, file := range files {
		output := processFile(file, strictMode, scanner)
		if err := encoder.Encode(output); err != nil {
			return fmt.Errorf("json encode failed: %w", err)
		}
	}
	return nil
}

func processFile(filename string, strictMode bool, scanner *semanticfw.PebbleScanner) FileOutput {
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return FileOutput{File: filename, ErrorMessage: err.Error()}
	}

	// Prevent DoS via OOM using LimitReader
	src, err := readSourceFile(absPath)
	if err != nil {
		return FileOutput{File: filename, ErrorMessage: err.Error()}
	}

	results, err := semanticfw.FingerprintSourceAdvanced(absPath, string(src), semanticfw.DefaultLiteralPolicy, strictMode)
	if err != nil {
		return FileOutput{File: filename, ErrorMessage: err.Error()}
	}

	output := FileOutput{
		File:      filename,
		Functions: make([]FunctionFingerprint, 0, len(results)),
	}

	for _, r := range results {
		output.Functions = append(output.Functions, FunctionFingerprint{
			Function:    r.FunctionName,
			Fingerprint: r.Fingerprint,
			File:        r.Filename,
			Line:        r.Line,
		})

		if scanner != nil {
			fn := r.GetSSAFunction()
			if fn != nil {
				topo := semanticfw.ExtractTopology(fn)
				if topo != nil {
					// Handle error return
					alerts, err := scanner.ScanTopology(topo, r.FunctionName)
					if err == nil {
						output.ScanResults = append(output.ScanResults, alerts...)
					} else {
						// Log error to stderr but don't fail the entire file output
						fmt.Fprintf(os.Stderr, "error scanning topology for %s: %v\n", r.FunctionName, err)
					}
				}
			}
		}
	}

	return output
}
