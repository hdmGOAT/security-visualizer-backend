package wrapper

import (
    "encoding/json"
    "fmt"
    "os/exec"
    "strings"

    "security-backend/internal/models"
)

// runCommand executes the binary with given args and returns stdout or an error
// that may include stderr. It also inspects JSON error shapes emitted on stdout
// for nicer error messages.
func (r *Runner) runCommand(args ...string) ([]byte, error) {
    // Print the command for debugging
    fmt.Printf("Executing: %s %s\n", r.binaryPath, strings.Join(args, " "))
    cmd := exec.Command(r.binaryPath, args...)
    output, err := cmd.Output()
    if err != nil {
        // If binary wrote a JSON error to stdout try to parse it
        if len(output) > 0 {
            var errResp struct{ Error string `json:"error"` }
            if jsonErr := json.Unmarshal(output, &errResp); jsonErr == nil && errResp.Error != "" {
                return nil, fmt.Errorf("C++ error: %s", errResp.Error)
            }
        }
        if exitErr, ok := err.(*exec.ExitError); ok {
            return nil, fmt.Errorf("C++ binary failed: %s, stderr: %s, stdout: %s", err, string(exitErr.Stderr), string(output))
        }
        return nil, fmt.Errorf("failed to run C++ binary: %w", err)
    }
    return output, nil
}

// GetGraph retrieves the graph structure from the C++ binary
func (r *Runner) GetGraph() (*models.GraphResponse, error) {
    output, err := r.runCommand("--mode", "graph", "--dot", r.dotPath, "--json")
    if err != nil {
        return nil, err
    }

    var response models.GraphResponse
    if err := json.Unmarshal(output, &response); err != nil {
        return nil, fmt.Errorf("failed to parse JSON output: %w, output: %s", err, string(output))
    }
    return &response, nil
}

// GetPDAGraph retrieves the PDA graph structure from the C++ binary
func (r *Runner) GetPDAGraph() (*models.GraphResponse, error) {
    output, err := r.runCommand("--mode", "graph", "--dot", r.pdaDotPath, "--json")
    if err != nil {
        return nil, err
    }

    var response models.GraphResponse
    if err := json.Unmarshal(output, &response); err != nil {
        return nil, fmt.Errorf("failed to parse JSON output: %w, output: %s", err, string(output))
    }
    return &response, nil
}
