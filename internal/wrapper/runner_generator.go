package wrapper

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// GenerateFromDataset runs the generator binary on the specified dataset file
// and returns the paths to the generated DOT and grammar files, along with the command output.
func (r *Runner) GenerateFromDataset(datasetPath string) (string, string, string, error) {
	// Create a temp directory for output
	tempDir := os.TempDir()
	dotPath := filepath.Join(tempDir, "generated_automaton.dot")
	grammarPath := filepath.Join(tempDir, "generated_grammar.txt")

	// Construct command: generator --input=<dataset> --export-dot=<dot> --export-grammar=<grammar>
	cmd := exec.Command(r.generatorPath,
		"--input="+datasetPath,
		"--export-dot="+dotPath,
		"--export-grammar="+grammarPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", string(output), fmt.Errorf("generator failed: %w, output: %s", err, string(output))
	}

	return dotPath, grammarPath, string(output), nil
}
