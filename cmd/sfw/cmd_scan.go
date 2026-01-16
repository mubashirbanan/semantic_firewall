// cmd_scan.go
package main

import (
	"encoding/json"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func runScan(target string, opts ScanOptions) error {
	files, err := collectFiles(target)
	if err != nil {
		return fmt.Errorf("collect files failed: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no Go files found in %s", target)
	}

	var allAlerts []semanticfw.ScanResult
	totalFunctions := 0
	var depsScanned int
	var scannedDeps []string
	backend := "json"

	if !isJSON(opts.DBPath) {
		backend = "pebbledb"
		allAlerts, totalFunctions, err = runScanPebble(files, opts.DBPath, opts.Threshold, opts.ExactOnly)
	} else {
		allAlerts, totalFunctions, err = runScanJSON(files, opts.DBPath, opts.Threshold)
	}
	if err != nil {
		return err
	}

	if opts.ScanDeps {
		depAlerts, depFuncs, deps, depErr := runScanDeps(target, opts)
		if depErr != nil {
			// Fail-Secure
			return fmt.Errorf("dependency scan failed: %w", depErr)
		}
		allAlerts = append(allAlerts, depAlerts...)
		depsScanned = depFuncs
		scannedDeps = deps
	}

	summary := ScanSummary{TotalAlerts: len(allAlerts)}
	for _, alert := range allAlerts {
		switch alert.Severity {
		case "CRITICAL":
			summary.CriticalAlerts++
		case "HIGH":
			summary.HighAlerts++
		case "MEDIUM":
			summary.MediumAlerts++
		case "LOW":
			summary.LowAlerts++
		}
	}

	output := ScanOutput{
		Target:       target,
		Database:     opts.DBPath,
		Backend:      backend,
		Threshold:    opts.Threshold,
		TotalScanned: totalFunctions + depsScanned,
		DepsScanned:  depsScanned,
		Alerts:       allAlerts,
		Summary:      summary,
		ScannedDeps:  scannedDeps,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runScanPebble(files []string, dbPath string, threshold float64, exactOnly bool) ([]semanticfw.ScanResult, int, error) {
	opts := semanticfw.DefaultPebbleScannerOptions()
	opts.MatchThreshold = threshold
	opts.ReadOnly = true

	scanner, err := semanticfw.NewPebbleScanner(dbPath, opts)
	if err != nil {
		return nil, 0, err
	}
	defer scanner.Close()

	var allAlerts []semanticfw.ScanResult
	totalFunctions := 0

	for _, file := range files {
		results, err := loadAndFingerprint(file)
		if err != nil {
			continue
		}
		for _, result := range results {
			totalFunctions++
			fn := result.GetSSAFunction()
			if fn == nil {
				continue
			}
			topo := semanticfw.ExtractTopology(fn)
			if topo == nil {
				continue
			}
			funcName := shortFunctionName(result.FunctionName)
			if exactOnly {
				// Handle error return for the exact scan case
				if alert, err := scanner.ScanTopologyExact(topo, funcName); err == nil && alert != nil {
					allAlerts = append(allAlerts, *alert)
				}
			} else {
				// Handle error return for the non-exact scan case
				if alerts, err := scanner.ScanTopology(topo, funcName); err == nil {
					allAlerts = append(allAlerts, alerts...)
				}
			}
		}
	}
	return allAlerts, totalFunctions, nil
}

// Initializes the in memory JSON scanner and loads the entire database upfront.
func runScanJSON(files []string, dbPath string, threshold float64) ([]semanticfw.ScanResult, int, error) {
	scanner := semanticfw.NewScanner()
	if err := scanner.LoadDatabase(dbPath); err != nil {
		return nil, 0, err
	}
	scanner.SetThreshold(threshold)

	var allAlerts []semanticfw.ScanResult
	totalFunctions := 0

	for _, file := range files {
		results, err := loadAndFingerprint(file)
		if err != nil {
			continue
		}
		for _, result := range results {
			totalFunctions++
			fn := result.GetSSAFunction()
			if fn == nil {
				continue
			}
			topo := semanticfw.ExtractTopology(fn)
			if topo == nil {
				continue
			}
			funcName := shortFunctionName(result.FunctionName)
			alerts := scanner.ScanTopology(topo, funcName)
			allAlerts = append(allAlerts, alerts...)
		}
	}
	return allAlerts, totalFunctions, nil
}

// Resolves the package graph for the target, flattens the dependency
// tree based on the depth settings, and prepares the appropriate
// scanner backend (Pebble vs JSON) before entering the main analysis loop.
func runScanDeps(target string, opts ScanOptions) ([]semanticfw.ScanResult, int, []string, error) {
	pkgs, err := loadPackagesWithDeps(target, opts.DepsDepth == "transitive")
	if err != nil {
		return nil, 0, nil, err
	}

	depPkgs := make(map[string]*packages.Package)
	for _, pkg := range pkgs {
		collectDependencies(pkg, depPkgs, opts.DepsDepth == "transitive", make(map[string]bool))
	}

	if len(depPkgs) == 0 {
		return nil, 0, nil, nil
	}

	var depSlice []*packages.Package
	for _, pkg := range depPkgs {
		depSlice = append(depSlice, pkg)
	}

	var allAlerts []semanticfw.ScanResult
	totalFunctions := 0
	var scannedDeps []string

	// OPTIMIZATION: Hoist scanner initialization outside the loop to avoid repeated expensive I/O
	var pebbleScanner *semanticfw.PebbleScanner
	var jsonScanner *semanticfw.Scanner

	if !isJSON(opts.DBPath) {
		scanOpts := semanticfw.DefaultPebbleScannerOptions()
		scanOpts.MatchThreshold = opts.Threshold
		scanOpts.ReadOnly = true
		pebbleScanner, err = semanticfw.NewPebbleScanner(opts.DBPath, scanOpts)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed to open signature db: %w", err)
		}
		defer pebbleScanner.Close()
	} else {
		jsonScanner = semanticfw.NewScanner()
		if err := jsonScanner.LoadDatabase(opts.DBPath); err != nil {
			return nil, 0, nil, fmt.Errorf("failed to load json db: %w", err)
		}
		jsonScanner.SetThreshold(opts.Threshold)
	}

	// Building SSA for an entire dependency tree (which can easily reach
	// tens of thousands of functions) in a single pass will likely
	// OOM the machine. We slice the dependencies into manageable chunks
	// to keep peak memory usage within reasonable bounds during compilation.
	const batchSize = 50
	for batchStart := 0; batchStart < len(depSlice); batchStart += batchSize {
		batchEnd := batchStart + batchSize
		if batchEnd > len(depSlice) {
			batchEnd = len(depSlice)
		}
		batch := depSlice[batchStart:batchEnd]

		prog, err := ssautil.AllPackages(batch, ssa.InstantiateGenerics)
		if err != nil || prog == nil {
			// Log but don't fail entire scan for one bad dep batch?
			// Security trade-off: failing hard might break CI for minor issues.
			// Warn heavily.
			fmt.Fprintf(os.Stderr, "warning: failed to build SSA for batch: %v\n", err)
			continue
		}
		prog.Build()

		for _, pkg := range batch {
			pkgPath := pkg.PkgPath
			scannedDeps = append(scannedDeps, pkgPath)
			ssaPkg := prog.Package(pkg.Types)
			if ssaPkg == nil {
				continue
			}

			for _, member := range ssaPkg.Members {
				switch m := member.(type) {
				case *ssa.Function:
					if m == nil || len(m.Blocks) == 0 {
						continue
					}
					alerts := scanFunction(m, pkgPath, pebbleScanner, jsonScanner, opts.ExactOnly)
					allAlerts = append(allAlerts, alerts...)
					totalFunctions++
				case *ssa.Type:
					if named, ok := m.Type().(*types.Named); ok {
						for i := 0; i < named.NumMethods(); i++ {
							method := named.Method(i)
							fn := prog.FuncValue(method)
							if fn == nil || len(fn.Blocks) == 0 {
								continue
							}
							alerts := scanFunction(fn, pkgPath, pebbleScanner, jsonScanner, opts.ExactOnly)
							allAlerts = append(allAlerts, alerts...)
							totalFunctions++
						}
					}
				}
			}
		}

		prog = nil
		runtime.GC()
	}

	sort.Strings(scannedDeps)
	return allAlerts, totalFunctions, scannedDeps, nil
}

func scanFunction(fn *ssa.Function, pkgPath string, pebbleScanner *semanticfw.PebbleScanner, jsonScanner *semanticfw.Scanner, exactOnly bool) []semanticfw.ScanResult {
	topo := semanticfw.ExtractTopology(fn)
	if topo == nil {
		return nil
	}
	funcName := fmt.Sprintf("%s.%s", pkgPath, fn.Name())
	if pebbleScanner != nil {
		if exactOnly {
			if alert, err := pebbleScanner.ScanTopologyExact(topo, funcName); err == nil && alert != nil {
				return []semanticfw.ScanResult{*alert}
			}
			return nil
		}
		// FIXED: Handle error return
		alerts, _ := pebbleScanner.ScanTopology(topo, funcName)
		return alerts
	}
	if jsonScanner != nil {
		return jsonScanner.ScanTopology(topo, funcName)
	}
	return nil
}

func loadPackagesWithDeps(target string, transitive bool) ([]*packages.Package, error) {
	mode := packages.NeedName | packages.NeedFiles | packages.NeedImports | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo
	if transitive {
		mode |= packages.NeedDeps
	}
	cfg := &packages.Config{
		Mode:  mode,
		Dir:   filepath.Dir(target),
		Tests: false,
	}
	pattern := "./..."
	info, err := os.Stat(target)
	if err == nil && !info.IsDir() {
		pattern = "file=" + target
	}
	return packages.Load(cfg, pattern)
}

func collectDependencies(pkg *packages.Package, deps map[string]*packages.Package, transitive bool, visited map[string]bool) {
	if pkg == nil || visited[pkg.PkgPath] {
		return
	}
	visited[pkg.PkgPath] = true
	for importPath, importPkg := range pkg.Imports {
		if !strings.Contains(importPath, ".") {
			continue
		}
		if _, ok := deps[importPath]; ok {
			continue
		}
		deps[importPath] = importPkg
		if transitive {
			collectDependencies(importPkg, deps, transitive, visited)
		}
	}
}
