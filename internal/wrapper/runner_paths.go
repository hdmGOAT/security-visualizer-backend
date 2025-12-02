package wrapper

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// Path to the binary relative to the project root
	BinaryPath     = "external/bin/api"
	GrammarPath    = "external/data/grammar.txt"
	DotPath        = "external/data/automaton.dot"
	PDADotPath     = "external/data/pda.dot"
	PDAGrammarPath = "external/data/pda_grammar.txt"
)

// Runner handles execution of the C++ binary
type Runner struct {
	binaryPath     string
	grammarPath    string
	dotPath        string
	pdaDotPath     string
	pdaGrammarPath string
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
	pdaGrammarPath, _ := filepath.Abs(PDAGrammarPath)
	return &Runner{
		binaryPath:     binPath,
		grammarPath:    gramPath,
		dotPath:        dotPath,
		pdaDotPath:     pdaDotPath,
		pdaGrammarPath: pdaGrammarPath,
	}
}
