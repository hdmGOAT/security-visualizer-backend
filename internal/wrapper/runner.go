package wrapper

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"security-backend/internal/models"
)

const (
	// Path to the binary relative to the project root
	BinaryPath = "external/bin/api"
	GrammarPath = "external/data/grammar.txt"
	DotPath     = "external/data/automaton.dot"
)

// Runner handles execution of the C++ binary
type Runner struct {
	binaryPath  string
	grammarPath string
	dotPath     string
}

// NewRunner creates a new Runner
func NewRunner() *Runner {
	binPath, _ := filepath.Abs(BinaryPath)
	gramPath, _ := filepath.Abs(GrammarPath)
	dotPath, _ := filepath.Abs(DotPath)
	return &Runner{
		binaryPath:  binPath,
		grammarPath: gramPath,
		dotPath:     dotPath,
	}
}

// GetGraph retrieves the graph structure from the C++ binary
func (r *Runner) GetGraph() (*models.GraphResponse, error) {
	fmt.Printf("Executing GetGraph: %s --mode graph --dot %s\n", r.binaryPath, r.dotPath)
	cmd := exec.Command(r.binaryPath, "--mode", "graph", "--dot", r.dotPath, "--json")
	
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			var errResp struct {
				Error string `json:"error"`
			}
			if jsonErr := json.Unmarshal(output, &errResp); jsonErr == nil && errResp.Error != "" {
				return nil, fmt.Errorf("C++ error: %s", errResp.Error)
			}
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("C++ binary failed: %s, stderr: %s, stdout: %s", err, string(exitErr.Stderr), string(output))
		}
		return nil, fmt.Errorf("failed to run C++ binary: %w", err)
	}

	var response models.GraphResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("failed to parse JSON output: %w, output: %s", err, string(output))
	}

	return &response, nil
}

// RunDFAStep executes the binary in DFA mode
func (r *Runner) RunDFAStep(currentState string, input models.Packet) (*models.DFAPacketResponse, error) {
	// Construct input string: "proto,service,conn_state"
	// Adjust based on what the C++ parser expects. 
	// Spec says: "proto", "service", "conn_state", optionally "history"
	// The C++ parser expects "proto=tcp,service=http,state=SF" format for symbols if they are labeled sequences
	// But the DFA mode in main.cpp splits by comma and looks up transitions.
	// The transitions in the grammar are likely "proto=tcp", "service=http", "state=SF".
	// So we should construct the input as a sequence of these symbols.
	
	inputStr := fmt.Sprintf("proto=%s,service=%s,state=%s", input.Proto, input.Service, input.ConnState)

	fmt.Printf("Executing DFA Step: %s --mode dfa --dot %s --state %s --input %s\n", r.binaryPath, r.dotPath, currentState, inputStr)
	cmd := exec.Command(r.binaryPath, "--mode", "dfa", "--dot", r.dotPath, "--state", currentState, "--input", inputStr, "--json")
	
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			var errResp struct {
				Error string `json:"error"`
			}
			if jsonErr := json.Unmarshal(output, &errResp); jsonErr == nil && errResp.Error != "" {
				return nil, fmt.Errorf("C++ error: %s", errResp.Error)
			}
		}
		// Try to capture stderr for debugging
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("C++ binary failed: %s, stderr: %s, stdout: %s", err, string(exitErr.Stderr), string(output))
		}
		return nil, fmt.Errorf("failed to run C++ binary: %w", err)
	}

	var response models.DFAPacketResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("failed to parse JSON output: %w, output: %s", err, string(output))
	}

	return &response, nil
}

// RunDerivation executes the binary in derivation mode for a single packet
func (r *Runner) RunDerivation(packet models.Packet) ([]string, error) {
	// Construct input string: "proto=tcp,service=http,state=SF"
	// Skip empty or "-" fields to allow matching transitions that skip optional fields
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

	cmd := exec.Command(r.binaryPath, "--mode", "derivation", "--grammar", r.grammarPath, "--input", inputStr, "--json")

	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			var errResp struct {
				Error string `json:"error"`
			}
			if jsonErr := json.Unmarshal(output, &errResp); jsonErr == nil && errResp.Error != "" {
				return nil, fmt.Errorf("C++ error: %s", errResp.Error)
			}
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("C++ binary failed: %s, stderr: %s, stdout: %s", err, string(exitErr.Stderr), string(output))
		}
		return nil, fmt.Errorf("failed to run C++ binary: %w", err)
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

// RunPDAValidation executes the binary in PDA mode
func (r *Runner) RunPDAValidation(hostID string, history []string) (*models.PDAValidationResponse, error) {
	// Join history with spaces or commas as expected by C++
	inputStr := strings.Join(history, " ")

	cmd := exec.Command(r.binaryPath, "--mode", "pda", "--grammar", r.grammarPath, "--input", inputStr, "--json")

	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			var errResp struct {
				Error string `json:"error"`
			}
			if jsonErr := json.Unmarshal(output, &errResp); jsonErr == nil && errResp.Error != "" {
				return nil, fmt.Errorf("C++ error: %s", errResp.Error)
			}
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("C++ binary failed: %s, stderr: %s, stdout: %s", err, string(exitErr.Stderr), string(output))
		}
		return nil, fmt.Errorf("failed to run C++ binary: %w", err)
	}

	// The C++ output for PDA might not include HostID, so we wrap it
	// We expect the C++ to return { "valid": bool, "steps": [...] }
	type CPPDAResponse struct {
		Valid bool                    `json:"valid"`
		Steps []models.StackOperation `json:"steps"`
	}

	var cppResp CPPDAResponse
	if err := json.Unmarshal(output, &cppResp); err != nil {
		return nil, fmt.Errorf("failed to parse JSON output: %w, output: %s", err, string(output))
	}

	return &models.PDAValidationResponse{
		HostID:  hostID,
		IsValid: cppResp.Valid,
		Trace:   cppResp.Steps,
	}, nil
}
