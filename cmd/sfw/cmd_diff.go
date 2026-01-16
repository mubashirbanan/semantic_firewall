// cmd_diff.go
package main

import (
	"encoding/json"
	"os"
)

// -- DIFF COMMAND --

func runDiff(oldFile, newFile string) error {
	output, err := computeDiff(oldFile, newFile)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
