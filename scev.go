package semanticfw

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"math/big"

	"golang.org/x/tools/go/ssa"
)

// -- Section 4: Scalar Evolution (SCEV) Framework --

// Renamer is a function that maps an SSA value to its canonical name.
// This is used to ensure deterministic output regardless of SSA register naming.
type Renamer func(ssa.Value) string

// SCEV represents a scalar expression.
type SCEV interface {
	ssa.Value
	EvaluateAt(k *big.Int) *big.Int
	IsLoopInvariant(loop *Loop) bool
	String() string
	// StringWithRenamer returns a canonical string using the provided renamer
	// function to map SSA values to their canonical names (e.g., v0, v1).
	// This is critical for determinism: without it, raw SSA names (t0, t1)
	// would leak into fingerprints, breaking semantic equivalence.
	StringWithRenamer(r Renamer) string
}

// SCEVAddRec represents an Add Recurrence: {Start, +, Step}_L
// Reference: Section 4.1 The Add Recurrence Abstraction.
type SCEVAddRec struct {
	Start SCEV
	Step  SCEV
	Loop  *Loop
}

func (s *SCEVAddRec) EvaluateAt(k *big.Int) *big.Int {
	// Val(k) = Start + (Step * k)
	startVal := s.Start.EvaluateAt(k)
	stepVal := s.Step.EvaluateAt(k)
	if startVal == nil || stepVal == nil {
		return nil
	}
	term := new(big.Int).Mul(stepVal, k)
	return new(big.Int).Add(startVal, term)
}

func (s *SCEVAddRec) IsLoopInvariant(loop *Loop) bool {
	// An AddRec defined in loop L varies in loop L.
	if s.Loop == loop {
		return false
	}
	return s.Start.IsLoopInvariant(loop) && s.Step.IsLoopInvariant(loop)
}

func (s *SCEVAddRec) String() string {
	return fmt.Sprintf("{%s, +, %s}", s.Start.String(), s.Step.String())
}

func (s *SCEVAddRec) StringWithRenamer(r Renamer) string {
	return fmt.Sprintf("{%s, +, %s}", s.Start.StringWithRenamer(r), s.Step.StringWithRenamer(r))
}

// ssa.Value Stubs
func (s *SCEVAddRec) Name() string                  { return "scev_addrec" }
func (s *SCEVAddRec) Type() types.Type              { return types.Typ[types.Int] }
func (s *SCEVAddRec) Parent() *ssa.Function         { return nil }
func (s *SCEVAddRec) Referrers() *[]ssa.Instruction { return nil }
func (s *SCEVAddRec) Pos() token.Pos                { return token.NoPos }

// SCEVConstant represents a literal integer constant.
type SCEVConstant struct {
	Value *big.Int
}

func (s *SCEVConstant) EvaluateAt(k *big.Int) *big.Int {
	return new(big.Int).Set(s.Value)
}
func (s *SCEVConstant) IsLoopInvariant(loop *Loop) bool { return true }
func (s *SCEVConstant) String() string                  { return s.Value.String() }
func (s *SCEVConstant) StringWithRenamer(r Renamer) string {
	// Constants don't need renaming - they're literal values
	return s.Value.String()
}

// ssa.Value Stubs
func (s *SCEVConstant) Name() string                  { return s.Value.String() }
func (s *SCEVConstant) Type() types.Type              { return types.Typ[types.Int] }
func (s *SCEVConstant) Parent() *ssa.Function         { return nil }
func (s *SCEVConstant) Referrers() *[]ssa.Instruction { return nil }
func (s *SCEVConstant) Pos() token.Pos                { return token.NoPos }

// SCEVUnknown represents a symbolic value (e.g., parameter or unanalyzable instr).
type SCEVUnknown struct {
	Value       ssa.Value
	IsInvariant bool // Explicitly tracks invariance relative to the analysis loop scope
}

func (s *SCEVUnknown) EvaluateAt(k *big.Int) *big.Int { return nil }
func (s *SCEVUnknown) IsLoopInvariant(loop *Loop) bool {
	// Use the explicitly stored invariance status if this SCEVUnknown
	// was created by toSCEV with proper scope resolution
	if s.IsInvariant {
		return true
	}
	if s.Value == nil {
		return false
	}
	if _, ok := s.Value.(*ssa.Const); ok {
		return true
	}
	if instr, ok := s.Value.(ssa.Instruction); ok {
		// Invariant if defined outside the loop body
		return !loop.Blocks[instr.Block()]
	}
	return true
}
func (s *SCEVUnknown) String() string {
	var name string
	if s.Value != nil {
		name = s.Value.Name()
	} else {
		name = "?"
	}
	if s.IsInvariant {
		return name + "(inv)"
	}
	return name
}

func (s *SCEVUnknown) StringWithRenamer(r Renamer) string {
	var name string
	if s.Value != nil && r != nil {
		// Use the renamer to get canonical name (e.g., v0 instead of t4)
		name = r(s.Value)
	} else if s.Value != nil {
		name = s.Value.Name()
	} else {
		name = "?"
	}
	if s.IsInvariant {
		return name + "(inv)"
	}
	return name
}

// ssa.Value Stubs
func (s *SCEVUnknown) Name() string                  { return s.String() }
func (s *SCEVUnknown) Type() types.Type              { return types.Typ[types.Int] }
func (s *SCEVUnknown) Parent() *ssa.Function         { return nil }
func (s *SCEVUnknown) Referrers() *[]ssa.Instruction { return nil }
func (s *SCEVUnknown) Pos() token.Pos                { return token.NoPos }

// SCEVGenericExpr represents binary operations like Add/Mul for formulas.
type SCEVGenericExpr struct {
	Op token.Token
	X  SCEV
	Y  SCEV
}

func (s *SCEVGenericExpr) EvaluateAt(k *big.Int) *big.Int { return nil }
func (s *SCEVGenericExpr) IsLoopInvariant(loop *Loop) bool {
	return s.X.IsLoopInvariant(loop) && s.Y.IsLoopInvariant(loop)
}
func (s *SCEVGenericExpr) String() string {
	return fmt.Sprintf("(%s %s %s)", s.X.String(), s.Op.String(), s.Y.String())
}

func (s *SCEVGenericExpr) StringWithRenamer(r Renamer) string {
	return fmt.Sprintf("(%s %s %s)", s.X.StringWithRenamer(r), s.Op.String(), s.Y.StringWithRenamer(r))
}

// ssa.Value Stubs
func (s *SCEVGenericExpr) Name() string                  { return "scev_expr" }
func (s *SCEVGenericExpr) Type() types.Type              { return types.Typ[types.Int] }
func (s *SCEVGenericExpr) Parent() *ssa.Function         { return nil }
func (s *SCEVGenericExpr) Referrers() *[]ssa.Instruction { return nil }
func (s *SCEVGenericExpr) Pos() token.Pos                { return token.NoPos }

// -- Analysis Algorithms --

// AnalyzeSCEV is the main entry point for SCEV analysis on a LoopInfo.
func AnalyzeSCEV(info *LoopInfo) {
	for _, loop := range info.Loops {
		analyzeLoopRecursively(loop)
	}
}

func analyzeLoopRecursively(loop *Loop) {
	// Bottom-up analysis
	for _, child := range loop.Children {
		analyzeLoopRecursively(child)
	}

	// 1. Identify Induction Variables (Section 3.3)
	identifyInductionVariables(loop)

	// 2. Compute Trip Counts (Section 5)
	deriveTripCount(loop)
}

// identifyInductionVariables implements the SCC-based IV detection.
// Reference: Section 3.3 Algorithm: Identification in semanticfw.
func identifyInductionVariables(loop *Loop) {
	// 1. Collect Loop Instructions
	var loopInstrs []ssa.Instruction
	// BUG FIX: Iterate over function blocks to ensure deterministic order.
	// Previous implementation iterated over loop.Blocks (map), which caused
	// non-deterministic SCC finding and IV classification.
	for _, block := range loop.Header.Parent().Blocks {
		if loop.Blocks[block] {
			loopInstrs = append(loopInstrs, block.Instrs...)
		}
	}

	// 2. Build Local Dependency Graph & Find SCCs
	sccs := findLoopSCCs(loop, loopInstrs)

	for _, scc := range sccs {
		// Look for simple cycles involving a Header Phi
		var headerPhi *ssa.Phi
		for _, instr := range scc {
			if phi, ok := instr.(*ssa.Phi); ok && phi.Block() == loop.Header {
				headerPhi = phi
				break
			}
		}

		if headerPhi == nil {
			continue
		}

		// 3. Classify SCC
		classifyIV(loop, headerPhi, scc)
	}
}

// findLoopSCCs implements Tarjan's algorithm restricted to the loop body.
func findLoopSCCs(loop *Loop, instrs []ssa.Instruction) [][]ssa.Instruction {
	var sccs [][]ssa.Instruction
	index := 0
	indices := make(map[ssa.Instruction]int)
	lowLink := make(map[ssa.Instruction]int)
	stack := []ssa.Instruction{}
	onStack := make(map[ssa.Instruction]bool)

	var strongConnect func(v ssa.Instruction)
	strongConnect = func(v ssa.Instruction) {
		indices[v] = index
		lowLink[v] = index
		index++
		stack = append(stack, v)
		onStack[v] = true

		// Edges: Use-Def chains restricted to Loop Body
		// v depends on operands w
		ops := v.Operands(nil)
		for _, op := range ops {
			if w, ok := (*op).(ssa.Instruction); ok && loop.Blocks[w.Block()] {
				if _, visited := indices[w]; !visited {
					strongConnect(w)
					if lowLink[w] < lowLink[v] {
						lowLink[v] = lowLink[w]
					}
				} else if onStack[w] {
					if indices[w] < lowLink[v] {
						lowLink[v] = indices[w]
					}
				}
			}
		}

		if lowLink[v] == indices[v] {
			var component []ssa.Instruction
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				component = append(component, w)
				if w == v {
					break
				}
			}
			sccs = append(sccs, component)
		}
	}

	for _, instr := range instrs {
		if _, visited := indices[instr]; !visited {
			strongConnect(instr)
		}
	}
	return sccs
}

func classifyIV(loop *Loop, phi *ssa.Phi, scc []ssa.Instruction) {
	// Look for the update operation: BinOp in the SCC
	var binOp *ssa.BinOp
	for _, instr := range scc {
		if op, ok := instr.(*ssa.BinOp); ok {
			binOp = op
			break
		}
	}

	if binOp == nil {
		return
	}

	// Check pattern: Update = Phi Op Step
	var stepVal ssa.Value
	if binOp.X == phi {
		stepVal = binOp.Y
	} else if binOp.Y == phi {
		// BUG FIX: Logic Inversion/Semantic Corruption.
		// For SUB, Y == phi means (C - Phi). This is NOT a linear induction variable.
		// It creates an oscillating sequence (or divergent).
		// Treating it as Basic IV {Start, +, C} is a semantic error.
		if binOp.Op == token.SUB {
			return
		}
		stepVal = binOp.X
	} else {
		return
	}

	// Step must be Loop Invariant (for Basic IV)
	stepSCEV := toSCEV(stepVal, loop)
	if !stepSCEV.IsLoopInvariant(loop) {
		return // Polynomial IV or complex recurrence
	}

	// Find Start Value (Edge from Pre-header)
	// Phi has edges from Pre-header (outside) and Latch (inside)
	// Risk: This assumes Loop Simplify Form (single pre-header). If there are
	// multiple outside predecessors, we verify they all provide the same start value.
	var startVal ssa.Value
	var outsidePredCount int
	// Identify which edges come from outside and validate consistency
	for i, pred := range phi.Block().Preds {
		if !loop.Blocks[pred] {
			outsidePredCount++
			if startVal == nil {
				startVal = phi.Edges[i]
			} else {
				// Multiple outside predecessors - verify they provide the same value
				// For strict correctness, both should be identical or both constants with same value
				if startVal != phi.Edges[i] {
					// Check if both are the same constant value
					c1, ok1 := startVal.(*ssa.Const)
					c2, ok2 := phi.Edges[i].(*ssa.Const)
					if !ok1 || !ok2 || c1.Value == nil || c2.Value == nil {
						return // Inconsistent start values from multiple predecessors
					}
					// Compare constant values
					if c1.Value.Kind() != c2.Value.Kind() {
						return
					}
					if !constant.Compare(c1.Value, token.EQL, c2.Value) {
						return // Different constant values - ambiguous start
					}
				}
			}
		}
	}

	if startVal == nil {
		return
	}
	startSCEV := toSCEV(startVal, loop)

	iv := &InductionVariable{
		Phi:   phi,
		Start: startSCEV,
		Step:  stepSCEV,
	}

	switch binOp.Op {
	case token.ADD:
		iv.Type = IVTypeBasic
	case token.SUB:
		iv.Type = IVTypeBasic
		// Normalize subtraction to addition with negative step
		if c, ok := stepSCEV.(*SCEVConstant); ok {
			neg := new(big.Int).Neg(c.Value)
			iv.Step = &SCEVConstant{Value: neg}
		} else {
			iv.Step = &SCEVGenericExpr{Op: token.MUL, X: stepSCEV, Y: &SCEVConstant{Value: big.NewInt(-1)}}
		}
	case token.MUL:
		iv.Type = IVTypeGeometric
	default:
		return
	}

	loop.Inductions[phi] = iv
}

// deriveTripCount implements Algorithm from Section 5.2.
// TripCount formula: ⌈(Limit - Start) / Step⌉ for up-counting loops (i < N)
//
//	⌈(Start - Limit) / |Step|⌉ for down-counting loops (i > N)
func deriveTripCount(loop *Loop) {
	// Simplify: Single Exit loops only
	if len(loop.Exits) != 1 {
		loop.TripCount = &SCEVUnknown{Value: nil}
		return
	}

	exitBlock := loop.Exits[0]
	// Terminator must be If
	if len(exitBlock.Instrs) == 0 {
		return
	}
	ifInstr, ok := exitBlock.Instrs[len(exitBlock.Instrs)-1].(*ssa.If)
	if !ok {
		return
	}

	// Condition must be a comparison
	binOp, ok := ifInstr.Cond.(*ssa.BinOp)
	if !ok {
		return
	}

	// Validate comparison operator - we only handle relational comparisons
	var isUpCounting bool
	var ivOnLeft bool
	switch binOp.Op {
	case token.LSS, token.LEQ: // i < N or i <= N (up-counting when IV is on left)
		isUpCounting = true
		ivOnLeft = true
	case token.GTR, token.GEQ: // i > N or i >= N (down-counting when IV is on left)
		isUpCounting = false
		ivOnLeft = true
	case token.EQL, token.NEQ:
		// Equality comparisons are harder to analyze; bail out
		loop.TripCount = &SCEVUnknown{Value: nil}
		return
	default:
		return
	}

	// Match IV vs Invariant
	var iv *InductionVariable
	var limit ssa.Value

	findIV := func(v ssa.Value) *InductionVariable {
		if phi, ok := v.(*ssa.Phi); ok {
			return loop.Inductions[phi]
		}
		return nil
	}

	if found := findIV(binOp.X); found != nil {
		iv = found
		limit = binOp.Y
		// IV is on left side, use the operator direction as-is
	} else if found := findIV(binOp.Y); found != nil {
		iv = found
		limit = binOp.X
		// IV is on right side, flip the direction interpretation
		// e.g., "N > i" is equivalent to "i < N" (up-counting)
		ivOnLeft = !ivOnLeft
		isUpCounting = !isUpCounting
	}

	if iv == nil || iv.Type != IVTypeBasic {
		return
	}

	limitSCEV := toSCEV(limit, loop)
	if !limitSCEV.IsLoopInvariant(loop) {
		return
	}

	// Validate step direction matches loop direction
	// Up-counting loops should have positive step, down-counting should have negative
	stepConst, stepIsConst := iv.Step.(*SCEVConstant)
	if stepIsConst {
		stepSign := stepConst.Value.Sign()
		if isUpCounting && stepSign <= 0 {
			// Up-counting loop with non-positive step - infinite or no iterations
			loop.TripCount = &SCEVUnknown{Value: nil}
			return
		}
		if !isUpCounting && stepSign >= 0 {
			// Down-counting loop with non-negative step - infinite or no iterations
			loop.TripCount = &SCEVUnknown{Value: nil}
			return
		}
	}

	// Calculate Diff based on loop direction
	// Up-counting: Diff = Limit - Start
	// Down-counting: Diff = Start - Limit
	var diff SCEV
	if isUpCounting || !ivOnLeft {
		// Standard case: Diff = Limit - Start
		var negStart SCEV
		if sConst, ok := iv.Start.(*SCEVConstant); ok {
			negStart = &SCEVConstant{Value: new(big.Int).Neg(sConst.Value)}
		} else {
			negStart = &SCEVGenericExpr{Op: token.MUL, X: &SCEVConstant{Value: big.NewInt(-1)}, Y: iv.Start}
		}
		diff = foldSCEV(token.ADD, limitSCEV, negStart, loop)
	} else {
		// Down-counting: Diff = Start - Limit
		var negLimit SCEV
		if lConst, ok := limitSCEV.(*SCEVConstant); ok {
			negLimit = &SCEVConstant{Value: new(big.Int).Neg(lConst.Value)}
		} else {
			negLimit = &SCEVGenericExpr{Op: token.MUL, X: &SCEVConstant{Value: big.NewInt(-1)}, Y: limitSCEV}
		}
		diff = foldSCEV(token.ADD, iv.Start, negLimit, loop)
	}

	// For down-counting loops, use absolute value of step
	var effectiveStep SCEV = iv.Step
	if !isUpCounting && stepIsConst && stepConst.Value.Sign() < 0 {
		effectiveStep = &SCEVConstant{Value: new(big.Int).Abs(stepConst.Value)}
	}

	// TripCount = Ceiling(Diff / Step)
	// BUG FIX: Correct Ceiling Division Formula: (Diff + Step - 1) / Step
	// Previously used integer truncation which is incorrect for strided loops.
	dConst, dOk := diff.(*SCEVConstant)
	sConst, sOk := effectiveStep.(*SCEVConstant)

	if dOk && sOk && sConst.Value.Sign() > 0 {
		num := new(big.Int).Add(dConst.Value, sConst.Value)
		num.Sub(num, big.NewInt(1))
		res := new(big.Int).Div(num, sConst.Value)
		loop.TripCount = &SCEVConstant{Value: res}
		return
	}

	// Fallback: Return a symbolic expression
	loop.TripCount = foldSCEV(token.QUO, diff, effectiveStep, loop)
}

func toSCEV(v ssa.Value, loop *Loop) SCEV {
	// Handle constants first - they are always loop invariant
	if c, ok := v.(*ssa.Const); ok {
		return SCEVFromConst(c)
	}

	// Phase 2: Scope Resolution - Determine if value is defined inside or outside the loop
	if instr, ok := v.(ssa.Instruction); ok {
		block := instr.Block()
		if block != nil && !loop.Blocks[block] {
			// Condition A: Instruction is defined outside the loop - it's invariant
			return &SCEVUnknown{Value: v, IsInvariant: true}
		}
		// Condition B: Instruction is inside the loop - proceed to recursive analysis
	}

	// Phase 3: Recursive AddRec Construction - Handle Phi nodes at loop header
	if phi, ok := v.(*ssa.Phi); ok {
		if phi.Block() == loop.Header {
			// Lookup Strategy: Check if this Phi was identified as an induction variable
			if iv, exists := loop.Inductions[phi]; exists {
				// Return the pre-calculated AddRec from IV analysis
				return &SCEVAddRec{
					Start: iv.Start,
					Step:  iv.Step,
					Loop:  loop,
				}
			}
		}
		// Fallback: Phi not recognized as IV, return as unknown
		return &SCEVUnknown{Value: v, IsInvariant: false}
	}

	// Phase 4: Recursive Folding and Simplification - Handle Binary Operations
	if binOp, ok := v.(*ssa.BinOp); ok {
		leftSCEV := toSCEV(binOp.X, loop)
		rightSCEV := toSCEV(binOp.Y, loop)
		return foldSCEV(binOp.Op, leftSCEV, rightSCEV, loop)
	}

	// Default: Return as unknown, check invariance based on instruction location
	if instr, ok := v.(ssa.Instruction); ok {
		block := instr.Block()
		isInvariant := block != nil && !loop.Blocks[block]
		return &SCEVUnknown{Value: v, IsInvariant: isInvariant}
	}

	// Non-instruction values (e.g., parameters, free variables) are loop invariant
	return &SCEVUnknown{Value: v, IsInvariant: true}
}

func SCEVFromConst(c *ssa.Const) *SCEVConstant {
	if c.Value == nil {
		return &SCEVConstant{Value: big.NewInt(0)}
	}
	if c.Value.Kind() == constant.Int {
		if val, ok := constant.Int64Val(c.Value); ok {
			return &SCEVConstant{Value: big.NewInt(val)}
		}
	}
	return &SCEVConstant{Value: big.NewInt(0)}
}

// foldSCEV attempts to simplify a binary operation on two SCEV expressions.
// It implements constant folding and AddRec simplification rules.
func foldSCEV(op token.Token, left, right SCEV, loop *Loop) SCEV {
	// Rule 1: Constant + Constant -> New Constant
	lConst, lIsConst := left.(*SCEVConstant)
	rConst, rIsConst := right.(*SCEVConstant)

	if lIsConst && rIsConst {
		result := new(big.Int)
		switch op {
		case token.ADD:
			result.Add(lConst.Value, rConst.Value)
		case token.SUB:
			result.Sub(lConst.Value, rConst.Value)
		case token.MUL:
			result.Mul(lConst.Value, rConst.Value)
		case token.QUO:
			if rConst.Value.Sign() != 0 {
				result.Div(lConst.Value, rConst.Value)
			} else {
				// Division by zero - return generic expression
				return &SCEVGenericExpr{Op: op, X: left, Y: right}
			}
		default:
			// Unsupported operation for constant folding
			return &SCEVGenericExpr{Op: op, X: left, Y: right}
		}
		return &SCEVConstant{Value: result}
	}

	// Rule 2: AddRec + Invariant -> {Start + Invariant, +, Step}
	// Also handles Invariant + AddRec due to commutativity of ADD
	if op == token.ADD {
		if addRec, ok := left.(*SCEVAddRec); ok && right.IsLoopInvariant(loop) {
			newStart := foldSCEV(token.ADD, addRec.Start, right, loop)
			return &SCEVAddRec{
				Start: newStart,
				Step:  addRec.Step,
				Loop:  addRec.Loop,
			}
		}
		if addRec, ok := right.(*SCEVAddRec); ok && left.IsLoopInvariant(loop) {
			newStart := foldSCEV(token.ADD, addRec.Start, left, loop)
			return &SCEVAddRec{
				Start: newStart,
				Step:  addRec.Step,
				Loop:  addRec.Loop,
			}
		}
	}

	// Rule 3: AddRec - Invariant -> {Start - Invariant, +, Step}
	if op == token.SUB {
		if addRec, ok := left.(*SCEVAddRec); ok && right.IsLoopInvariant(loop) {
			newStart := foldSCEV(token.SUB, addRec.Start, right, loop)
			return &SCEVAddRec{
				Start: newStart,
				Step:  addRec.Step,
				Loop:  addRec.Loop,
			}
		}
	}

	// Rule 4: Invariant * AddRec -> {Invariant * Start, +, Invariant * Step}
	if op == token.MUL {
		if addRec, ok := left.(*SCEVAddRec); ok && right.IsLoopInvariant(loop) {
			newStart := foldSCEV(token.MUL, addRec.Start, right, loop)
			newStep := foldSCEV(token.MUL, addRec.Step, right, loop)
			return &SCEVAddRec{
				Start: newStart,
				Step:  newStep,
				Loop:  addRec.Loop,
			}
		}
		if addRec, ok := right.(*SCEVAddRec); ok && left.IsLoopInvariant(loop) {
			newStart := foldSCEV(token.MUL, addRec.Start, left, loop)
			newStep := foldSCEV(token.MUL, addRec.Step, left, loop)
			return &SCEVAddRec{
				Start: newStart,
				Step:  newStep,
				Loop:  addRec.Loop,
			}
		}
	}

	// Fallback: Return a generic expression if no simplification applies
	return &SCEVGenericExpr{Op: op, X: left, Y: right}
}
