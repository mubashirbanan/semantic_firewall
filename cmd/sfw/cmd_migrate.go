// cmd_migrate.go
package main

import (
	"encoding/json"
	"fmt"
	"os"

	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

func runMigrate(fromPath, toPath string) error {
	scanner, err := semanticfw.NewPebbleScanner(toPath, semanticfw.DefaultPebbleScannerOptions())
	if err != nil {
		return err
	}
	defer scanner.Close()
	count, err := scanner.MigrateFromJSON(fromPath)
	if err != nil {
		return err
	}
	output := struct {
		Message string `json:"message"`
		Source  string `json:"source"`
		Dest    string `json:"destination"`
		Count   int    `json:"signatures_migrated"`
	}{
		Message: fmt.Sprintf("Successfully migrated %d signatures", count),
		Source:  fromPath,
		Dest:    toPath,
		Count:   count,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
