// cmd_audit.go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// -- AUDIT COMMAND --

func runAudit(w io.Writer, oldFile, newFile, commitMsg, apiKey, model, apiBase string) (int, error) {
	diff, err := computeDiff(oldFile, newFile)
	if err != nil {
		return 0, fmt.Errorf("diff computation failed: %w", err)
	}

	var evidence []AuditEvidence
	for _, fn := range diff.Functions {
		if fn.RiskScore >= 10 {
			ops := strings.Join(fn.AddedOps, ", ")
			if len(fn.AddedOps) > 10 {
				ops = fmt.Sprintf("%s (+%d more)", strings.Join(fn.AddedOps[:10], ", "), len(fn.AddedOps)-10)
			}

			evidence = append(evidence, AuditEvidence{
				Function:        fn.Function,
				RiskScore:       fn.RiskScore,
				StructuralDelta: fn.TopologyDelta,
				AddedOperations: ops,
			})
		}
	}

	highRiskDetected := len(evidence) > 0

	output := AuditOutput{
		Inputs: AuditInputs{
			CommitMessage: commitMsg,
		},
		RiskFilter: RiskFilterStats{
			HighRiskDetected: highRiskDetected,
			EvidenceCount:    len(evidence),
		},
	}

	if highRiskDetected {
		result, err := callLLM(commitMsg, evidence, apiKey, model, apiBase)
		if err != nil {
			// FAIL-CLOSED: System errors should typically fail the audit or alert
			output.Output = LLMResult{
				Verdict:  "ERROR",
				Evidence: fmt.Sprintf("Verification Failed: %v", err),
			}
		} else {
			output.Output = result
		}
	} else {
		output.Output = LLMResult{
			Verdict:  "MATCH",
			Evidence: "Automatic Pass: No structural escalation detected.",
		}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return 0, fmt.Errorf("json encode failed: %w", err)
	}

	if output.Output.Verdict == "LIE" || output.Output.Verdict == "ERROR" {
		return 1, nil
	}

	return 0, nil
}
