// diff.go
package main

import (
	"fmt"
	"strings"

	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

func computeDiff(oldFile, newFile string) (*DiffOutput, error) {
	oldResults, err := loadAndFingerprint(oldFile)
	if err != nil {
		// Handle non-existent old file (creation event)
		oldResults = []semanticfw.FingerprintResult{}
	}

	newResults, err := loadAndFingerprint(newFile)
	if err != nil {
		// Handle non-existent new file (deletion event)
		newResults = []semanticfw.FingerprintResult{}
	}

	matched, addedFuncs, removedFuncs := semanticfw.MatchFunctionsByTopology(
		oldResults, newResults, 0.6,
	)

	var functionDiffs []FunctionDiff
	var topologyMatches []TopologyMatchInfo
	preserved, modified, renamed, highRisk := 0, 0, 0, 0

	for _, m := range matched {
		oldShort := shortFunctionName(m.OldResult.FunctionName)
		newShort := shortFunctionName(m.NewResult.FunctionName)

		diff := compareFunctions(oldShort, m.OldResult, m.NewResult)

		if !m.ByName {
			diff.Function = fmt.Sprintf("%s → %s", oldShort, newShort)
			renamed++
		}

		if diff.Status == "modified" && m.OldTopology != nil && m.NewTopology != nil {
			delta, riskScore := calculateTopologyDelta(m.OldTopology, m.NewTopology)
			diff.TopologyDelta = delta
			diff.RiskScore = riskScore
			if riskScore >= 10 {
				highRisk++
			}
		}

		functionDiffs = append(functionDiffs, diff)
		if diff.Status == "preserved" {
			preserved++
		} else {
			modified++
		}

		oldTopoStr := ""
		if m.OldTopology != nil {
			oldTopoStr = semanticfw.TopologyFingerprint(m.OldTopology)
		}
		newTopoStr := ""
		if m.NewTopology != nil {
			newTopoStr = semanticfw.TopologyFingerprint(m.NewTopology)
		}

		topologyMatches = append(topologyMatches, TopologyMatchInfo{
			OldFunction:   oldShort,
			NewFunction:   newShort,
			Similarity:    m.Similarity,
			MatchedByName: m.ByName,
			OldTopology:   oldTopoStr,
			NewTopology:   newTopoStr,
		})
	}

	// Bypass vulnerability.
	// Previously, added functions had a static risk score of 5.
	// Now we analyze their topology to detect high-risk features (loops, C2 calls).
	for _, r := range addedFuncs {
		risk := 5
		delta := "NewFunction"

		fn := r.GetSSAFunction()
		if fn != nil {
			topo := semanticfw.ExtractTopology(fn)
			if topo != nil {
				// Passing nil as oldT allows delta calc against empty state
				d, s := calculateTopologyDelta(nil, topo)
				delta = d
				risk = s
			}
		}

		if risk >= 10 {
			highRisk++
		}

		functionDiffs = append(functionDiffs, FunctionDiff{
			Function:       shortFunctionName(r.FunctionName),
			Status:         "added",
			NewFingerprint: r.Fingerprint,
			RiskScore:      risk,
			TopologyDelta:  delta,
		})
	}

	for _, r := range removedFuncs {
		functionDiffs = append(functionDiffs, FunctionDiff{
			Function:       shortFunctionName(r.FunctionName),
			Status:         "removed",
			OldFingerprint: r.Fingerprint,
		})
	}

	added := len(addedFuncs)
	removed := len(removedFuncs)
	total := len(matched) + added + removed
	matchPct := 0.0
	topoMatchPct := 0.0
	if total > 0 {
		matchPct = float64(preserved) / float64(total) * 100.0
	}
	if len(matched) > 0 {
		topoMatchPct = float64(len(matched)) / float64(total) * 100.0
	}

	return &DiffOutput{
		OldFile: oldFile,
		NewFile: newFile,
		Summary: DiffSummary{
			TotalFunctions:     total,
			Preserved:          preserved,
			Modified:           modified,
			Added:              added,
			Removed:            removed,
			SemanticMatchPct:   matchPct,
			TopologyMatchedPct: topoMatchPct,
			RenamedFunctions:   renamed,
			HighRiskChanges:    highRisk,
		},
		Functions:       functionDiffs,
		TopologyMatches: topologyMatches,
	}, nil
}

func calculateTopologyDelta(oldT, newT *semanticfw.FunctionTopology) (string, int) {
	// If new is nil, assume no change or error
	if newT == nil {
		return "Unknown", 0
	}
	// Handle nil oldT for Added functions
	if oldT == nil {
		oldT = &semanticfw.FunctionTopology{}
	}

	var deltas []string
	riskScore := 0

	callDiff := len(newT.CallSignatures) - len(oldT.CallSignatures)
	if callDiff > 0 {
		deltas = append(deltas, fmt.Sprintf("Calls+%d", callDiff))
		riskScore += callDiff * 5
	} else if callDiff < 0 {
		deltas = append(deltas, fmt.Sprintf("Calls%d", callDiff))
	}

	loopDiff := newT.LoopCount - oldT.LoopCount
	if loopDiff > 0 {
		deltas = append(deltas, fmt.Sprintf("Loops+%d", loopDiff))
		riskScore += loopDiff * 10
	} else if loopDiff < 0 {
		deltas = append(deltas, fmt.Sprintf("Loops%d", loopDiff))
	}

	branchDiff := newT.BranchCount - oldT.BranchCount
	if branchDiff > 0 {
		deltas = append(deltas, fmt.Sprintf("Branches+%d", branchDiff))
		riskScore += branchDiff * 2
	} else if branchDiff < 0 {
		deltas = append(deltas, fmt.Sprintf("Branches%d", branchDiff))
	}

	if newT.HasGo && !oldT.HasGo {
		deltas = append(deltas, "AddedGoroutine")
		riskScore += 15
	}

	if newT.HasDefer && !oldT.HasDefer {
		deltas = append(deltas, "AddedDefer")
		riskScore += 3
	}

	if newT.HasPanic && !oldT.HasPanic {
		deltas = append(deltas, "AddedPanic")
		riskScore += 5
	}

	entropyDiff := newT.EntropyScore - oldT.EntropyScore
	if entropyDiff > 1.0 {
		deltas = append(deltas, fmt.Sprintf("Entropy+%.1f", entropyDiff))
		riskScore += int(entropyDiff * 3)
	}

	if len(deltas) == 0 {
		return "NoStructuralChange", 0
	}

	return strings.Join(deltas, ", "), riskScore
}

func compareFunctions(funcName string, oldResult, newResult semanticfw.FingerprintResult) FunctionDiff {
	diff := FunctionDiff{
		Function:       funcName,
		OldFingerprint: oldResult.Fingerprint,
		NewFingerprint: newResult.Fingerprint,
	}

	if oldResult.Fingerprint == newResult.Fingerprint {
		diff.Status = "preserved"
		diff.FingerprintMatch = true
		return diff
	}

	diff.FingerprintMatch = false
	oldFn := oldResult.GetSSAFunction()
	newFn := newResult.GetSSAFunction()

	if oldFn == nil || newFn == nil {
		diff.Status = "modified"
		return diff
	}

	zipper, err := semanticfw.NewZipper(oldFn, newFn, semanticfw.DefaultLiteralPolicy)
	if err != nil {
		diff.Status = "modified"
		return diff
	}

	artifacts, err := zipper.ComputeDiff()
	if err != nil {
		diff.Status = "modified"
		return diff
	}

	diff.MatchedNodes = artifacts.MatchedNodes
	diff.AddedOps = artifacts.Added
	diff.RemovedOps = artifacts.Removed

	if artifacts.Preserved {
		diff.Status = "preserved"
	} else {
		diff.Status = "modified"
	}

	return diff
}
