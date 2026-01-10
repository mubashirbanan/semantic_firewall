package semanticfw

import (
	"fmt"
	"sort"

	"golang.org/x/tools/go/ssa"
)

// -- Section 7.1 Data Structures --

// LoopInfo summarizes loop analysis for a single function.
type LoopInfo struct {
	Function *ssa.Function
	Loops    []*Loop // Top-level loops (roots of the hierarchy)
	// Map from Header block to Loop object for O(1) lookup
	LoopMap map[*ssa.BasicBlock]*Loop
}

// Loop represents a natural loop in the SSA graph.
// Reference: Section 2.3 Natural Loops.
type Loop struct {
	Header *ssa.BasicBlock
	Latch  *ssa.BasicBlock // Primary source of the backedge

	// Blocks contains all basic blocks within the loop body.
	Blocks map[*ssa.BasicBlock]bool
	// Exits contains blocks inside the loop that have successors outside.
	Exits []*ssa.BasicBlock

	// Hierarchy
	Parent   *Loop
	Children []*Loop

	// Semantic Analysis (populated in scev.go)
	Inductions map[*ssa.Phi]*InductionVariable
	TripCount  SCEV // Symbolic expression
}

func (l *Loop) String() string {
	return fmt.Sprintf("L_%s", l.Header.String())
}

// InductionVariable describes a detected IV.
// Reference: Section 3.2 Classification Taxonomy.
type InductionVariable struct {
	Phi   *ssa.Phi
	Type  IVType
	Start SCEV // Value at iteration 0
	Step  SCEV // Update stride
}

type IVType int

const (
	IVTypeUnknown    IVType = iota
	IVTypeBasic             // {S, +, C}
	IVTypeDerived           // Affine: A * IV + B
	IVTypeGeometric         // {S, *, C}
	IVTypePolynomial        // Step is another IV
)

// DetectLoops reconstructs the loop hierarchy using dominance relations.
// Reference: Section 2.3.1 Algorithm: Detecting Natural Loops.
func DetectLoops(fn *ssa.Function) *LoopInfo {
	// Ensure dominator tree is computed for the function
	_ = fn.DomPreorder()

	info := &LoopInfo{
		Function: fn,
		LoopMap:  make(map[*ssa.BasicBlock]*Loop),
	}

	if len(fn.Blocks) == 0 {
		return info
	}

	// 1. Scan for Backedges: Edge B -> H where H dominates B.
	// We group latches by header to handle natural loops with multiple backedges.
	headerToLatches := make(map[*ssa.BasicBlock][]*ssa.BasicBlock)
	var headers []*ssa.BasicBlock

	for _, b := range fn.Blocks {
		for _, succ := range b.Succs {
			// Section 7.3: Filter out 'recover' edges to avoid topology distortion
			if succ == fn.Recover {
				continue
			}

			// ssa.BasicBlock.Dominates provides the dominance check.
			if succ.Dominates(b) {
				if _, exists := headerToLatches[succ]; !exists {
					headers = append(headers, succ)
				}
				headerToLatches[succ] = append(headerToLatches[succ], b)
			}
		}
	}

	// Ensure deterministic processing order
	sort.Slice(headers, func(i, j int) bool { return headers[i].Index < headers[j].Index })

	var allLoops []*Loop

	for _, header := range headers {
		latches := headerToLatches[header]
		// Construct the loop
		// Heuristic: Use the first latch as the primary one for analysis
		loop := &Loop{
			Header:     header,
			Latch:      latches[0],
			Blocks:     make(map[*ssa.BasicBlock]bool),
			Inductions: make(map[*ssa.Phi]*InductionVariable),
			Children:   make([]*Loop, 0),
		}

		// 3. Construct the Loop Body (Worklist Algorithm)
		constructLoopBody(loop, latches)

		// Identify Exiting Blocks (Section 5.1)
		for b := range loop.Blocks {
			for _, succ := range b.Succs {
				if !loop.Blocks[succ] {
					loop.Exits = append(loop.Exits, b)
					break // This block is an exit
				}
			}
		}

		// BUG FIX: Sort exits to ensure deterministic order.
		// Iteration over loop.Blocks (map) above makes order random.
		sort.Slice(loop.Exits, func(i, j int) bool {
			return loop.Exits[i].Index < loop.Exits[j].Index
		})

		allLoops = append(allLoops, loop)
		info.LoopMap[header] = loop
	}

	// 4. Handle Nested Loops (Hierarchy Construction)
	// A loop A is nested in B if A's header is in B's body.
	// We want the *innermost* container to be the parent.
	for _, child := range allLoops {
		var bestParent *Loop
		bestSize := int(^uint(0) >> 1) // Max int

		for _, candidate := range allLoops {
			if child == candidate {
				continue
			}
			if candidate.Blocks[child.Header] {
				// child is inside candidate
				// We prefer the candidate with the smallest body size (tightest nesting)
				size := len(candidate.Blocks)
				if size < bestSize {
					bestSize = size
					bestParent = candidate
				}
			}
		}

		if bestParent != nil {
			child.Parent = bestParent
			bestParent.Children = append(bestParent.Children, child)
		} else {
			info.Loops = append(info.Loops, child)
		}
	}

	return info
}

// constructLoopBody builds the set of blocks in the natural loop.
// Algorithm from Section 2.3.1 Step 3.
func constructLoopBody(loop *Loop, latches []*ssa.BasicBlock) {
	loop.Blocks[loop.Header] = true

	// Initialize worklist with all latches
	var worklist []*ssa.BasicBlock
	for _, l := range latches {
		loop.Blocks[l] = true
		worklist = append(worklist, l)
	}

	for len(worklist) > 0 {
		// Pop
		curr := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]

		if curr == loop.Header {
			continue
		}

		for _, pred := range curr.Preds {
			if !loop.Blocks[pred] {
				loop.Blocks[pred] = true
				worklist = append(worklist, pred)
			}
		}
	}
}
