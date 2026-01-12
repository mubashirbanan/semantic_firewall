# Semantic Firewall

**Detect logic corruption that bypasses code reviews.**

[![Go Reference](https://pkg.go.dev/badge/github.com/BlackVectorOps/semantic_firewall.svg)](https://pkg.go.dev/github.com/BlackVectorOps/semantic_firewall)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Marketplace](https://img.shields.io/badge/Marketplace-Semantic%20Firewall-blue.svg)](https://github.com/marketplace/actions/semantic-firewall)
[![Semantic Check](https://github.com/BlackVectorOps/semantic_firewall/actions/workflows/semantic-check.yml/badge.svg)](https://github.com/BlackVectorOps/semantic_firewall/actions/workflows/semantic-check.yml)

---

Semantic Firewall generates deterministic fingerprints of your Go code's **behavior**, not its bytes. It uses **Scalar Evolution (SCEV)** analysis to prove that syntactically different loops are mathematically identical, and a **Semantic Zipper** to diff architectural changes without the noise.

---

## Quick Start

```bash
# Install
go install github.com/BlackVectorOps/semantic_firewall/cmd/sfw@latest

# Fingerprint a file
sfw check ./main.go

# Semantic diff between two versions
sfw diff old_version.go new_version.go
```

**Check Output:**
```json
{
  "file": "./main.go",
  "functions": [
    { "function": "main", "fingerprint": "005efb52a8c9d1e3..." }
  ]
}
```

**Diff Output (The Zipper):**
```json
{
  "summary": {
    "semantic_match_pct": 92.5,
    "preserved": 12,
    "modified": 1
  },
  "functions": [
    {
      "function": "HandleLogin",
      "status": "modified",
      "added_ops": ["Call <log.Printf>", "Call <net.Dial>"],
      "removed_ops": []
    }
  ]
}
```

---

## Why Use This?

**"Don't unit tests solve this?"** No. Unit tests verify *correctness* (does input A produce output B?). `sfw` verifies *intent* and *integrity*.

- A developer refactors a function but secretly adds a network call → **unit tests pass, `sfw` fails.**
- A developer changes a `switch` to a Strategy Pattern → **`git diff` shows 100 lines changed, `sfw diff` shows zero logic changes.**

| Traditional Tooling | Semantic Firewall |
|---------------------|-------------------|
| **Git Diff** — Shows lines changed (whitespace, renaming = noise) | **sfw check** — Verifies control flow graph identity |
| **Unit Tests** — Verify input/output (blind to side effects) | **sfw diff** — Isolates actual logic drift from cosmetic changes |

**Use cases:**
- **Supply chain security** — Detect backdoors like the xz attack that pass code review
- **Safe refactoring** — Prove your refactor didn't change behavior
- **CI/CD gates** — Block PRs that alter critical function logic

---

## CI Integration: Blocker & Reporter Modes

`sfw` supports two distinct CI roles:

1. **Blocker Mode:** When a PR claims to be a refactor (via title or `semantic-safe` label), `sfw` enforces strict semantic equivalence. Any logic change fails the build.

2. **Reporter Mode:** On feature PRs, `sfw` runs a semantic diff and generates a drift report (e.g., "Semantic Match: 80%"), helping reviewers focus on the code where behavior actually changed.

### GitHub Action (Easiest)

Drop this into your workflow for **Blocker Mode**—enforces semantic immutability on every PR:

```yaml
- uses: BlackVectorOps/semantic_firewall@v1
  with:
    path: './'
    go-version: '1.24'
```

> **Note:** The Marketplace Action runs `sfw check` (Blocker Mode). For semantic diff reports (Reporter Mode), use the CLI configuration below.

### Advanced: Full Workflow with Reporter Mode

```yaml
name: Semantic Firewall

on:
  pull_request:
    branches: [ "main" ]
    types: [opened, synchronize, reopened, labeled]

jobs:
  semantic-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Install sfw
        run: go install github.com/BlackVectorOps/semantic_firewall/cmd/sfw@latest

      - name: Determine Mode
        id: mode
        run: |
          if [[ "${{ contains(github.event.pull_request.labels.*.name, 'semantic-safe') }}" == "true" ]] || \
             [[ "${{ contains(github.event.pull_request.title, 'refactor') }}" == "true" ]]; then
            echo "mode=BLOCKER" >> $GITHUB_OUTPUT
          else
            echo "mode=REPORTER" >> $GITHUB_OUTPUT
          fi

      - name: Run Blocker Check
        if: steps.mode.outputs.mode == 'BLOCKER'
        run: sfw check ./

      - name: Run Reporter Diff
        if: steps.mode.outputs.mode == 'REPORTER'
        run: |
          BASE_SHA=${{ github.event.pull_request.base.sha }}
          git diff --name-only "$BASE_SHA" HEAD -- '*.go' | while read file; do
            [ -f "$file" ] || continue
            git show "$BASE_SHA:$file" > old.go 2>/dev/null || touch old.go
            sfw diff old.go "$file" | jq .
            rm old.go
          done
```

---

## Library Usage

```go
import semanticfw "github.com/BlackVectorOps/semantic_firewall"

src := `package main
func Add(a, b int) int { return a + b }
`

results, err := semanticfw.FingerprintSource("example.go", src, semanticfw.DefaultLiteralPolicy)
if err != nil {
    log.Fatal(err)
}

for _, r := range results {
    fmt.Printf("%s: %s\n", r.FunctionName, r.Fingerprint)
}
```

---

## Technical Deep Dive

<details>
<summary><strong>Click to expand: Architecture & Algorithms</strong></summary>

### Pipeline Overview

```
Source → SSA → Loop Analysis → SCEV → Canonicalization → SHA-256
          ↓         ↓            ↓            ↓
      go/ssa    Tarjan's     Symbolic     Virtual IR
                 SCC        Evaluation   Normalization
```

1. **SSA Construction** — `golang.org/x/tools/go/ssa` converts source to Static Single Assignment form with explicit control flow graphs
2. **Loop Detection** — Natural loop identification via backedge detection (edge B→H where H dominates B)
3. **SCEV Analysis** — Algebraic characterization of loop variables as closed-form recurrences
4. **Canonicalization** — Deterministic IR transformation: register renaming, branch normalization, loop virtualization
5. **Fingerprint** — SHA-256 of canonical IR string

### Scalar Evolution (SCEV) Engine

The SCEV framework (`scev.go`, 746 LOC) solves the "loop equivalence problem"—proving that syntactically different loops compute the same sequence of values.

**Core Abstraction: Add Recurrences**

An induction variable is represented as $\{Start, +, Step\}_L$, meaning at iteration $k$ the value is:

$$Val(k) = Start + (Step \times k)$$

This representation is closed under affine transformations:

| Operation | Result |
|-----------|--------|
| $\{S, +, T\} + C$ | $\{S+C, +, T\}$ |
| $C \times \{S, +, T\}$ | $\{C \times S, +, C \times T\}$ |
| $\{S_1, +, T_1\} + \{S_2, +, T_2\}$ | $\{S_1+S_2, +, T_1+T_2\}$ |

**IV Detection Algorithm (Tarjan's SCC)**

```
1. Build dependency graph restricted to loop body
2. Find SCCs via Tarjan's algorithm (O(V+E))
3. For each SCC containing a header Phi:
   a. Extract cycle: Phi → BinOp → Phi
   b. Classify: Basic ({S,+,C}), Geometric ({S,*,C}), Polynomial
   c. Verify step is loop-invariant
4. Propagate SCEV to derived expressions via recursive folding
```

**Trip Count Derivation**

For a loop `for i := Start; i < Limit; i += Step`:

$$TripCount = \left\lceil \frac{Limit - Start}{Step} \right\rceil$$

Computed via ceiling division: `(Limit - Start + Step - 1) / Step`

The engine handles:
- Up-counting (`i < N`) and down-counting (`i > N`) loops
- Inclusive bounds (`i <= N` → add 1 to numerator)
- Negative steps (normalized to absolute value)
- Multi-predecessor loop headers (validates consistent start values)

### Canonicalization Engine

The canonicalizer (`canonicalizer.go`, 1162 LOC) transforms SSA into a deterministic string representation via five phases:

**Phase 1: Loop & SCEV Analysis**
```go
c.loopInfo = DetectLoops(fn)
AnalyzeSCEV(c.loopInfo)
```

**Phase 2: Semantic Normalization**
- **Invariant Hoisting**: Pure calls like `len(s)` are virtually moved to pre-header
- **IV Virtualization**: Phi nodes for IVs are replaced with SCEV notation `{0, +, 1}`
- **Derived IV Propagation**: Expressions like `i*4` become `{0, +, 4}` in output

**Phase 3: Register Renaming**
```
Parameters: p0, p1, p2, ...
Free Variables: fv0, fv1, ...
Instructions: v0, v1, v2, ... (DFS order)
```

**Phase 4: Deterministic Block Ordering**

Blocks are traversed in dominance-respecting DFS order, ensuring identical output regardless of SSA construction order. Successor ordering is normalized:
- `>=` branches are rewritten to `<` with swapped successors
- `>` branches are rewritten to `<=` with swapped successors

**Phase 5: Virtual Control Flow**

Branch normalization is applied *virtually* (no SSA mutation) via lookup tables:
```go
virtualBlocks map[*ssa.BasicBlock]*virtualBlock  // swapped successors
virtualBinOps map[*ssa.BinOp]token.Token         // normalized operators
```

### The Semantic Zipper

The Zipper (`zipper.go`, 568 LOC) computes a semantic diff between two functions—what actually changed in behavior, ignoring cosmetic differences.

**Algorithm: Parallel Graph Traversal**

```
PHASE 0: Semantic Analysis
  - Run SCEV on both functions independently
  - Build canonicalizers for operand comparison

PHASE 1: Anchor Alignment
  - Map parameters positionally: oldFn.Params[i] ↔ newFn.Params[i]
  - Map free variables if counts match
  - Seed entry block via sequential matching (critical for main())

PHASE 2: Forward Propagation (BFS on Use-Def chains)
  while queue not empty:
    (vOld, vNew) = dequeue()
    for each user uOld of vOld:
      candidates = users of vNew with matching structural fingerprint
      for uNew in candidates:
        if areEquivalent(uOld, uNew):
          map(uOld, uNew)
          enqueue((uOld, uNew))
          break

PHASE 2.5: Terminator Scavenging
  - Explicitly match Return/Panic instructions via operand equivalence
  - Handles cases where terminators aren't reached via normal propagation

PHASE 3: Divergence Isolation
  - Added = newFn instructions not in reverse map
  - Removed = oldFn instructions not in forward map
```

**Equivalence Checking**

Two instructions are equivalent iff:
1. Same Go type (`reflect.TypeOf`)
2. Same SSA value type (`types.Identical`)
3. Same operation-specific properties (BinOp.Op, Field index, Alloc.Heap, etc.)
4. All operands equivalent (recursive, with commutativity handling for ADD/MUL/AND/OR/XOR)

**Structural Fingerprinting (DoS Prevention)**

To prevent $O(N \times M)$ comparisons on high-fanout values, users are bucketed by structural fingerprint:
```go
fp := fmt.Sprintf("%T:%s", instr, op)  // e.g., "*ssa.BinOp:+"
candidates := newByOp[fp]              // Only compare compatible types
```

Bucket size is capped at 100 to bound worst-case complexity.

### Security Hardening

| Threat | Mitigation |
|--------|------------|
| **Algorithmic DoS** (exponential SCEV) | Memoization cache per-loop: `loop.SCEVCache` |
| **Quadratic Zipper** (5000 identical ADDs) | Fingerprint bucketing + `MaxCandidates=100` |
| **RCE via CGO** | `CGO_ENABLED=0` during `packages.Load` |
| **SSRF via module fetch** | `GOPROXY=off` prevents network calls |
| **Stack overflow** (cyclic graphs) | Visited sets in all recursive traversals |
| **NaN comparison instability** | Branch normalization restricted to `IsInteger \| IsString` types |
| **IR injection** (fake instructions in strings) | Struct tags and literals sanitized before hashing |
| **TypeParam edge cases** | Generic types excluded from branch swap (may hide floats) |

### Complexity Analysis

| Operation | Time | Space |
|-----------|------|-------|
| SSA Construction | $O(N)$ | $O(N)$ |
| Loop Detection | $O(V+E)$ | $O(V)$ |
| SCEV Analysis | $O(L \times I)$ amortized | $O(I)$ per loop |
| Canonicalization | $O(I \times \log B)$ | $O(I + B)$ |
| Zipper | $O(I^2)$ worst, $O(I)$ typical | $O(I)$ |

Where $N$ = source size, $V$ = blocks, $E$ = edges, $L$ = loops, $I$ = instructions, $B$ = blocks.

</details>

---

## License

MIT License — See [LICENSE](LICENSE) for details.
