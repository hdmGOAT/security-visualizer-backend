package wrapper

import (
	"encoding/json"
	"fmt"
	"strings"

	"security-backend/internal/models"
)

// RunDFAStep executes the binary in DFA mode for a single packet
func (r *Runner) RunDFAStep(currentState string, input models.Packet) (*models.DFAPacketResponse, error) {
	// Construct input string: "proto=...,service=...,state=..."
	inputStr := fmt.Sprintf("proto=%s,service=%s,state=%s", input.Proto, input.Service, input.ConnState)

	output, err := r.runCommand("--mode", "dfa", "--dot", r.dotPath, "--state", currentState, "--input", inputStr, "--json")
	if err != nil {
		return nil, err
	}

	var response models.DFAPacketResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("failed to parse JSON output: %w, output: %s", err, string(output))
	}
	return &response, nil
}

// RunDerivation executes the binary in derivation mode for a single packet
func (r *Runner) RunDerivation(packet models.Packet) ([]string, error) {
	// Build input sequence, skipping empty or placeholder fields
	var symbols []string
	if packet.Proto != "" && packet.Proto != "-" {
		symbols = append(symbols, fmt.Sprintf("proto=%s", packet.Proto))
	}
	if packet.Service != "" && packet.Service != "-" {
		symbols = append(symbols, fmt.Sprintf("service=%s", packet.Service))
	}
	if packet.ConnState != "" && packet.ConnState != "-" {
		symbols = append(symbols, fmt.Sprintf("state=%s", packet.ConnState))
	}
	inputStr := strings.Join(symbols, ",")

	output, err := r.runCommand("--mode", "derivation", "--grammar", r.grammarPath, "--input", inputStr, "--json")
	if err != nil {
		return nil, err
	}

	type DerivationResponse struct {
		Steps []string `json:"steps"`
	}
	var response DerivationResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("failed to parse JSON output: %w, output: %s", err, string(output))
	}
	return response.Steps, nil
}

// GetGrammar retrieves the DFA grammar text via the C++ binary
func (r *Runner) GetGrammar() (*models.GrammarResponse, error) {
	output, err := r.runCommand("--mode", "grammar", "--grammar", r.grammarPath, "--json")
	if err != nil {
		return nil, err
	}

	var response models.GrammarResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("failed to parse JSON output: %w, output: %s", err, string(output))
	}
	return &response, nil
}
