package wrapper

import (
    "encoding/json"
    "fmt"
    "strings"

    "security-backend/internal/models"
)

// RunPDAValidation executes the binary in PDA mode
func (r *Runner) RunPDAValidation(history []string) (*models.PDAValidationResponse, error) {
    // Ensure PDA history ends with terminating symbol expected by the PDA (END)
    if len(history) == 0 || history[len(history)-1] != "END" {
        history = append(history, "END")
    }

    inputStr := strings.Join(history, " ")

    // Use the PDA .dot file when invoking PDA mode
    fmt.Printf("Executing PDA: %s --mode pda --dot %s --input '%s' --json\n", r.binaryPath, r.pdaDotPath, inputStr)
    output, err := r.runCommand("--mode", "pda", "--dot", r.pdaDotPath, "--input", inputStr, "--json")
    if err != nil {
        return nil, err
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
        Valid bool        `json:"valid"`
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
        IsValid: cppResp.Valid,
        Trace:   trace,
    }, nil
}
