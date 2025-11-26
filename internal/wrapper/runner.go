package wrapper

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"security-backend/internal/models"
)

const (
	// Path to the binary relative to the project root
	BinaryPath = "external/bin/api"
	GrammarPath = "external/data/grammar.txt"
	DotPath     = "external/data/automaton.dot"
	PDADotPath  = "external/data/pda.dot"
)

// Runner handles execution of the C++ binary
type Runner struct {
	binaryPath  string
	grammarPath string
	dotPath     string
	pdaDotPath  string
}

// NewRunner creates a new Runner
func NewRunner() *Runner {
	// Resolve the binary name for the current platform. On Windows prefer
	// `api.exe` but fall back to the plain `api` if the .exe is not present
	// (e.g., when running in WSL or using a Linux-built binary).
	binCandidate := BinaryPath
	if runtime.GOOS == "windows" {
		binCandidate = BinaryPath + ".exe"
	}

	// If the preferred candidate doesn't exist, fall back to the other name.
	if _, err := os.Stat(binCandidate); os.IsNotExist(err) {
		// try the other variant
		alt := BinaryPath
		if strings.HasSuffix(binCandidate, ".exe") {
			alt = BinaryPath
		} else {
			alt = BinaryPath + ".exe"
		}
		if _, err2 := os.Stat(alt); err2 == nil {
			binCandidate = alt
		}
	}

	binPath, _ := filepath.Abs(binCandidate)
	gramPath, _ := filepath.Abs(GrammarPath)
	dotPath, _ := filepath.Abs(DotPath)
	pdaDotPath, _ := filepath.Abs(PDADotPath)
	return &Runner{
		binaryPath:  binPath,
		grammarPath: gramPath,
		dotPath:     dotPath,
		pdaDotPath:  pdaDotPath,
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
	// Ensure the PDA history ends with the terminating symbol expected by the PDA (END)
	// The PDA uses bare symbols for conn states (e.g., "S0"), so append plain "END".
	if len(history) == 0 || history[len(history)-1] != "END" {
		history = append(history, "END")
	}

	inputStr := strings.Join(history, " ")

	// Use the PDA .dot file when invoking PDA mode
	// Print the exact command and input so callers can inspect what's passed to the C++ CLI
	fmt.Printf("Executing PDA: %s --mode pda --dot %s --input '%s' --json\n", r.binaryPath, r.pdaDotPath, inputStr)
	cmd := exec.Command(r.binaryPath, "--mode", "pda", "--dot", r.pdaDotPath, "--input", inputStr, "--json")

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

	// The C++ output for PDA is expected to be: { "valid": bool, "steps": [ { "op":..., "symbol":..., "stack": [...], "current_state":..., "next_state":... }, ... ] }
	type CPPDAStep struct {
		Op           string   `json:"op"`
		Symbol       string   `json:"symbol"`
		Stack        []string `json:"stack"`
		CurrentState string   `json:"current_state"`
		NextState    string   `json:"next_state"`
	}
	type CPPDAResponse struct {
		Valid bool       `json:"valid"`
		Steps []CPPDAStep `json:"steps"`
	}

	var cppResp CPPDAResponse
	if err := json.Unmarshal(output, &cppResp); err != nil {
		return nil, fmt.Errorf("failed to parse JSON output: %w, output: %s", err, string(output))
	}

	// Convert to models.StackOperation with additional mapping (include control states)
	var trace []models.StackOperation
	for i, s := range cppResp.Steps {
		trace = append(trace, models.StackOperation{
			StepIndex:    i,
			Action:       s.Op,
			Symbol:       s.Symbol,
			Stack:        s.Stack,
			CurrentState: s.CurrentState,
			NextState:    s.NextState,
		})
	}

	return &models.PDAValidationResponse{
		HostID:  hostID,
		IsValid: cppResp.Valid,
		Trace:   trace,
	}, nil
}

// GetPDAGraph retrieves the PDA graph structure from the C++ binary
func (r *Runner) GetPDAGraph() (*models.GraphResponse, error) {
	fmt.Printf("Executing GetPDAGraph: %s --mode graph --dot %s\n", r.binaryPath, r.pdaDotPath)
	cmd := exec.Command(r.binaryPath, "--mode", "graph", "--dot", r.pdaDotPath, "--json")

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

// RunRequest processes a high-level request composed of multiple packets.
// It will:
// - Build a PDA history (sequence of terminals) from the packets and run the PDA validator
// - For each packet, run the DFA step(s) starting from the start state (stateless per-packet)
// Returns combined result including PDA response and per-packet DFA responses
func (r *Runner) RunRequest(hostID string, packets []models.Packet, threshold int) (*models.RequestProcessingResponse, error) {
	// Build PDA history: expand each packet to the sequence [proto=..., service=..., state=...]
	var history []string
	for _, p := range packets {
		if p.Proto != "" && p.Proto != "-" {
			history = append(history, "proto="+p.Proto)
		}
		if p.Service != "" && p.Service != "-" {
			history = append(history, "service="+p.Service)
		}
		if p.ConnState != "" && p.ConnState != "-" {
			history = append(history, "state="+p.ConnState)
		}
	}

	pdaResp, err := r.RunPDAValidation(hostID, history)
	if err != nil {
		return nil, err
	}

	// For per-packet DFA processing, we run each packet starting from the start state `s4`.
	var packetResults []models.DFAPacketResponse
	for _, p := range packets {
		// Keep stateless per-packet as requested (start from s4)
		dres, err := r.RunDFAStep("s4", p)
		if err != nil {
			// On error, include a simple error-like DFAPacketResponse
			packetResults = append(packetResults, models.DFAPacketResponse{
				Steps:      []models.DFAStep{},
				FinalState: "error",
				IsMalicious: false,
				Label:      fmt.Sprintf("error: %v", err),
			})
			continue
		}
		packetResults = append(packetResults, *dres)
	}

	// Decide whether the whole request is malicious based on the provided threshold.
	maliciousCount := 0
	for _, pr := range packetResults {
		if pr.IsMalicious {
			maliciousCount++
		}
	}

	overallMalicious := false
	if threshold > 0 && maliciousCount >= threshold {
		overallMalicious = true
	}

	return &models.RequestProcessingResponse{
		PDA:        *pdaResp,
		Packets:    packetResults,
		IsMalicious: overallMalicious,
	}, nil
}
