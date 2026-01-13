package semanticfw

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// Holds everything we learned from fingerprinting a single function: the hash,
// the canonical IR that produced it, and the source location for traceability.
type FingerprintResult struct {
	FunctionName string
	Fingerprint  string
	CanonicalIR  string
	Pos          token.Pos
	Line         int
	Filename     string
	// fn stores the SSA function for advanced analysis (unexported for internal use)
	fn *ssa.Function
}

// Exposes the underlying SSA function for consumers that need deeper analysis,
// like semantic diffing with the Zipper algorithm. Returns nil if unavailable.
func (r FingerprintResult) GetSSAFunction() *ssa.Function {
	return r.fn
}

// Tracks virtual control flow modifications without touching the actual SSA graph.
// We record which blocks should have swapped successors and which BinOps should
// use different operators, then apply these during canonicalization.
type virtualControlFlowState struct {
	// swappedBlocks tracks blocks whose successors should be virtually swapped
	swappedBlocks map[*ssa.BasicBlock]bool
	// virtualBinOps tracks BinOp operators that should be virtually changed
	virtualBinOps map[*ssa.BinOp]token.Token
}

func newVirtualControlFlowState() *virtualControlFlowState {
	return &virtualControlFlowState{
		swappedBlocks: make(map[*ssa.BasicBlock]bool),
		virtualBinOps: make(map[*ssa.BinOp]token.Token),
	}
}

// Analyzes conditional branches and figures out what normalizations we need.
// Everything stays read only here; the SSA graph remains untouched.
func computeVirtualControlFlow(fn *ssa.Function) *virtualControlFlowState {
	state := newVirtualControlFlowState()

	for _, block := range fn.Blocks {
		if len(block.Instrs) == 0 {
			continue
		}
		// Check if the last instruction is an If
		if ifInstr, ok := block.Instrs[len(block.Instrs)-1].(*ssa.If); ok {
			// Check if the condition is a BinOp
			if binOp, ok := ifInstr.Cond.(*ssa.BinOp); ok {

				// Only swap operands if the type guarantees total ordering.
				// Never swap Floats, Complex, or Generic types.
				isSafeToSwap := func(t types.Type) bool {
					if basic, ok := t.Underlying().(*types.Basic); ok {
						return (basic.Info() & (types.IsInteger | types.IsString)) != 0
					}
					// Pointers, Floats, Complex, Interfaces, and TypeParams are NOT safe to swap.
					return false
				}

				if !isSafeToSwap(binOp.X.Type()) || !isSafeToSwap(binOp.Y.Type()) {
					continue
				}

				// Do not mutate BinOp if it has multiple referrers.
				// If the condition is stored in a variable and used elsewhere (e.g., returned),
				// mutating the operator corrupts the semantics of those other uses.
				if refs := binOp.Referrers(); refs != nil && len(*refs) > 1 {
					continue
				}

				var newOp token.Token
				swap := false
				switch binOp.Op {
				case token.GEQ: // >= becomes < with branch swap
					// Transformation: (a >= b) ? T : F  ≡  (a < b) ? F : T
					// This normalizes exit-on-GEQ patterns to continue-on-LSS patterns.
					newOp = token.LSS
					swap = true
				case token.GTR: // > becomes <= with branch swap
					// Transformation: (a > b) ? T : F  ≡  (a <= b) ? F : T
					// This normalizes exit-on-GTR patterns to continue-on-LEQ patterns.
					newOp = token.LEQ
					swap = true
				}

				if swap {
					// Defensive check to ensure exactly 2 successors before swapping
					if len(block.Succs) != 2 {
						continue
					}
					// Record virtual changes instead of mutating.
					// Both the operator change AND the branch swap are required
					// to preserve semantic equivalence while normalizing control flow.
					state.virtualBinOps[binOp] = newOp
					state.swappedBlocks[block] = true
				}
			}
		}
	}
	return state
}

// Produces the SHA256 hash and canonical string representation for an SSA function.
// Pulls a Canonicalizer from the pool to keep allocations low and throughput high.
func GenerateFingerprint(fn *ssa.Function, policy LiteralPolicy, strictMode bool) FingerprintResult {
	// Compute virtual control flow state without mutating
	virtualCF := computeVirtualControlFlow(fn)

	// Acquire a canonicalizer from the pool.
	// This satisfies the requirement to avoid a shared singleton while maintaining performance.
	canonicalizer := AcquireCanonicalizer(policy)
	defer ReleaseCanonicalizer(canonicalizer)

	canonicalizer.StrictMode = strictMode

	// Pass virtual state to canonicalizer using the direct method
	canonicalizer.ApplyVirtualControlFlowFromState(virtualCF.swappedBlocks, virtualCF.virtualBinOps)
	canonicalIR := canonicalizer.CanonicalizeFunction(fn)

	hash := sha256.Sum256([]byte(canonicalIR))
	fingerprint := hex.EncodeToString(hash[:])

	// Resolve position information here while Fset is available.
	line := 0
	filename := ""
	if fn.Prog != nil && fn.Prog.Fset != nil {
		p := fn.Prog.Fset.Position(fn.Pos())
		line = p.Line
		filename = p.Filename
	}

	return FingerprintResult{
		// Use RelString(nil) to get fully qualified names (e.g. (*Type).Method).
		FunctionName: fn.RelString(nil),
		Fingerprint:  fingerprint,
		CanonicalIR:  canonicalIR,
		Pos:          fn.Pos(),
		Line:         line,
		Filename:     filename,
		fn:           fn,
	}
}

// Analyzes a single Go source file provided as a string. Primary entry point
// for verifying code snippets or patch hunks.
func FingerprintSource(filename string, src string, policy LiteralPolicy) ([]FingerprintResult, error) {
	return FingerprintSourceAdvanced(filename, src, policy, false)
}

// Extended interface for source analysis that exposes strict mode control.
func FingerprintSourceAdvanced(filename string, src string, policy LiteralPolicy, strictMode bool) ([]FingerprintResult, error) {
	initialPkgs, err := loadPackagesFromSource(filename, src)
	if err != nil {
		return nil, err
	}

	return FingerprintPackages(initialPkgs, policy, strictMode)
}

// Loads packages from a provided source string for analysis.
func loadPackagesFromSource(filename string, src string) ([]*packages.Package, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("input source code is empty")
	}

	sourceDir := filepath.Dir(filename)
	absFilename, err := filepath.Abs(filename)
	if err != nil {
		absFilename = filename
	}

	fset := token.NewFileSet()

	// Defense-in-depth hardening against RCE and SSRF:
	// CGO_ENABLED=0 prevents RCE via malicious cgo directives.
	// GOPROXY=off prevents network module fetching.
	// GOFLAGS=-mod=readonly prevents go.mod/go.sum modification.
	// GONOSUMDB=* disables checksum database lookups.
	// GOWORK=off prevents workspace configuration tampering.
	// Filter env vars case-insensitively to handle platform differences.
	env := make([]string, 0, len(os.Environ())+6)
	for _, e := range os.Environ() {
		upperE := strings.ToUpper(e)
		switch {
		case strings.HasPrefix(upperE, "CGO_ENABLED="),
			strings.HasPrefix(upperE, "GOPROXY="),
			strings.HasPrefix(upperE, "GOFLAGS="),
			strings.HasPrefix(upperE, "GONOSUMDB="),
			strings.HasPrefix(upperE, "GOWORK="),
			strings.HasPrefix(upperE, "GO111MODULE="):
			// Skip conflicting variables (case-insensitive check)
			continue
		}
		env = append(env, e)
	}
	env = append(env, "CGO_ENABLED=0", "GOPROXY=off", "GOFLAGS=-mod=readonly", "GONOSUMDB=*", "GOWORK=off", "GO111MODULE=on")

	cfg := &packages.Config{
		Dir:  sourceDir,
		Mode: packages.LoadAllSyntax,
		Fset: fset,
		Overlay: map[string][]byte{
			absFilename: []byte(src),
		},
		Tests: false,
		Env:   env,
	}

	initialPkgs, err := packages.Load(cfg, "file="+absFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to execute loader: %w", err)
	}

	var errorMessages strings.Builder
	packages.Visit(initialPkgs, nil, func(pkg *packages.Package) {
		for _, e := range pkg.Errors {
			errorMessages.WriteString(e.Error() + "\n")
		}
	})

	if errorMessages.Len() > 0 {
		return nil, fmt.Errorf("packages contain errors: \n%s", errorMessages.String())
	}

	return initialPkgs, nil
}

// Walks the loaded packages, builds SSA, and generates fingerprint results for
// every function we find. Handles methods, closures, and init functions.
func FingerprintPackages(initialPkgs []*packages.Package, policy LiteralPolicy, strictMode bool) ([]FingerprintResult, error) {
	if len(initialPkgs) == 0 {
		return nil, fmt.Errorf("input packages list is empty")
	}

	prog, _, err := BuildSSAFromPackages(initialPkgs)
	if err != nil {
		return nil, fmt.Errorf("failed to build SSA: %w", err)
	}

	var results []FingerprintResult
	// Track visited functions to prevent infinite recursion
	// and duplicate processing across packages.
	visited := make(map[*ssa.Function]bool)

	// Iterate over all packages provided, not just the main one.
	for _, pkg := range initialPkgs {
		ssaPkg := prog.Package(pkg.Types)
		if ssaPkg == nil {
			continue
		}

		for _, member := range ssaPkg.Members {
			switch mem := member.(type) {
			case *ssa.Function:
				// Top-level functions (including init)
				processFunctionAndAnons(mem, policy, strictMode, &results, visited)
			case *ssa.Type:
				// Explicitly handle methods associated with named types.
				if named, ok := mem.Type().(*types.Named); ok {
					for i := 0; i < named.NumMethods(); i++ {
						m := named.Method(i)
						if fn := prog.FuncValue(m); fn != nil {
							processFunctionAndAnons(fn, policy, strictMode, &results, visited)
						}
					}
				}
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].FunctionName < results[j].FunctionName
	})

	return results, nil
}

// Recursively analyzes a function and any closures it defines. The visited map
// prevents infinite loops and duplicate processing.
func processFunctionAndAnons(fn *ssa.Function, policy LiteralPolicy, strictMode bool, results *[]FingerprintResult, visited map[*ssa.Function]bool) {
	// Prevent infinite recursion by tracking visited functions.
	if visited[fn] {
		return
	}
	visited[fn] = true

	// Process ALL functions including synthetic ones.
	// Synthetic functions include init() which contains global variable initialization.
	// We include synthetic functions but still require Blocks > 0.
	if len(fn.Blocks) > 0 {
		result := GenerateFingerprint(fn, policy, strictMode)
		*results = append(*results, result)
	}

	for _, anon := range fn.AnonFuncs {
		processFunctionAndAnons(anon, policy, strictMode, results, visited)
	}
}
