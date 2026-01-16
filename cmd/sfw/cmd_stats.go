// cmd_stats.go
package main

import (
	"encoding/json"
	"os"

	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

func runStats(dbPath string) error {
	if isJSON(dbPath) {
		scanner := semanticfw.NewScanner()
		if err := scanner.LoadDatabase(dbPath); err != nil {
			return err
		}
		db := scanner.GetDatabase()
		output := struct {
			Database       string `json:"database"`
			Backend        string `json:"backend"`
			Version        string `json:"version"`
			SignatureCount int    `json:"signature_count"`
		}{
			Database:       dbPath,
			Backend:        "json",
			Version:        db.Version,
			SignatureCount: len(db.Signatures),
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}

	opts := semanticfw.DefaultPebbleScannerOptions()
	opts.ReadOnly = true
	scanner, err := semanticfw.NewPebbleScanner(dbPath, opts)
	if err != nil {
		return err
	}
	defer scanner.Close()

	stats, err := scanner.Stats()
	if err != nil {
		return err
	}

	fileInfo, _ := os.Stat(dbPath)
	var fileSize int64
	if fileInfo != nil {
		fileSize = fileInfo.Size()
	}

	output := struct {
		Database          string `json:"database"`
		Backend           string `json:"backend"`
		SignatureCount    int    `json:"signature_count"`
		TopoIndexCount    int    `json:"topology_index_count"`
		EntropyIndexCount int    `json:"entropy_index_count"`
		FileSizeBytes     int64  `json:"file_size_bytes"`
		FileSizeHuman     string `json:"file_size_human"`
	}{
		Database:          dbPath,
		Backend:           "pebbledb",
		SignatureCount:    stats.SignatureCount,
		TopoIndexCount:    stats.TopoIndexCount,
		EntropyIndexCount: stats.EntropyIndexCount,
		FileSizeBytes:     fileSize,
		FileSizeHuman:     humanizeBytes(fileSize),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
