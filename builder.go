package semanticfw

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Constructs Static Single Assignment form from loaded Go packages.
// Returns the complete program and the target package for analysis.
func BuildSSAFromPackages(initialPkgs []*packages.Package) (*ssa.Program, *ssa.Package, error) {
	if len(initialPkgs) == 0 {
		return nil, nil, fmt.Errorf("input packages list is empty")
	}

	var errorMessages strings.Builder
	packages.Visit(initialPkgs, nil, func(pkg *packages.Package) {
		for _, e := range pkg.Errors {
			errorMessages.WriteString(e.Error() + "\n")
		}
	})

	// SECURITY IMPROVEMENT: Relaxed error handling.
	// Previously, we returned an error if *any* package had errors.
	// This prevented analyzing malware that imports missing packages.
	// Now we log them (optional) but proceed, as SSA construction
	// is often resilient enough to handle partial programs.
	if errorMessages.Len() > 0 {
		// In a real logging system, we'd log this. For now, we proceed.
		// return nil, nil, fmt.Errorf("packages contain errors: \n%s", errorMessages.String())
	}

	// Initializes the SSA program builder for all packages and dependencies.
	// Enable InstantiateGenerics so generic function bodies are built in Go 1.18+.
	mode := ssa.InstantiateGenerics
	prog, pkgs := ssautil.AllPackages(initialPkgs, mode)
	if prog == nil {
		return nil, nil, fmt.Errorf("failed to initialize SSA program builder")
	}

	prog.Build()

	mainPkg := initialPkgs[0]
	var ssaPkg *ssa.Package

	for i, p := range initialPkgs {
		if p == mainPkg && i < len(pkgs) && pkgs[i] != nil {
			ssaPkg = pkgs[i]
			break
		}
	}

	if ssaPkg == nil && mainPkg.Types != nil {
		ssaPkg = prog.Package(mainPkg.Types)
	}

	if ssaPkg == nil {
		return nil, nil, fmt.Errorf("could not find main SSA package for %s", mainPkg.ID)
	}

	return prog, ssaPkg, nil
}
