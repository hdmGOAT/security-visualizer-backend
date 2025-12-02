package api

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"

	"security-backend/internal/wrapper"
)

type ConfigHandler struct {
	runner *wrapper.Runner
}

func NewConfigHandler(r *wrapper.Runner) *ConfigHandler {
	return &ConfigHandler{runner: r}
}

type UploadConfigRequest struct {
	DotContent        string `json:"dotContent"`
	GrammarContent    string `json:"grammarContent"`
	PDADotContent     string `json:"pdaDotContent"`
	PDAGrammarContent string `json:"pdaGrammarContent"`
}

func (h *ConfigHandler) HandleUploadConfig(w http.ResponseWriter, r *http.Request) {
	var req UploadConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	tempDir := os.TempDir()

	var dotPath, grammarPath, pdaDotPath, pdaGrammarPath string

	if req.DotContent != "" {
		f, err := ioutil.TempFile(tempDir, "automaton_*.dot")
		if err != nil {
			http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
			return
		}
		if _, err := f.WriteString(req.DotContent); err != nil {
			http.Error(w, "Failed to write to temp file", http.StatusInternalServerError)
			return
		}
		f.Close()
		dotPath = f.Name()
	}

	if req.GrammarContent != "" {
		f, err := ioutil.TempFile(tempDir, "grammar_*.txt")
		if err != nil {
			http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
			return
		}
		if _, err := f.WriteString(req.GrammarContent); err != nil {
			http.Error(w, "Failed to write to temp file", http.StatusInternalServerError)
			return
		}
		f.Close()
		grammarPath = f.Name()
	}

	if req.PDADotContent != "" {
		f, err := ioutil.TempFile(tempDir, "pda_*.dot")
		if err != nil {
			http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
			return
		}
		if _, err := f.WriteString(req.PDADotContent); err != nil {
			http.Error(w, "Failed to write to temp file", http.StatusInternalServerError)
			return
		}
		f.Close()
		pdaDotPath = f.Name()
	}

	if req.PDAGrammarContent != "" {
		f, err := ioutil.TempFile(tempDir, "pda_grammar_*.txt")
		if err != nil {
			http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
			return
		}
		if _, err := f.WriteString(req.PDAGrammarContent); err != nil {
			http.Error(w, "Failed to write to temp file", http.StatusInternalServerError)
			return
		}
		f.Close()
		pdaGrammarPath = f.Name()
	}

	h.runner.SetPaths(dotPath, grammarPath, pdaDotPath, pdaGrammarPath)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

func (h *ConfigHandler) HandleResetConfig(w http.ResponseWriter, r *http.Request) {
	h.runner.ResetPaths()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
}
