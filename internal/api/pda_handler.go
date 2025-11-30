package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"security-backend/internal/wrapper"
)

type PDAHandler struct {
	runner *wrapper.Runner
}

func NewPDAHandler(r *wrapper.Runner) *PDAHandler {
	return &PDAHandler{runner: r}
}

// HandleValidate accepts POST { "input": "a b c" } or
// POST { "history": ["state=S0", ...] }
func (h *PDAHandler) HandleValidate(w http.ResponseWriter, r *http.Request) {
	type ValidateRequest struct {
		Input   string   `json:"input"`   // Direct input for testing
		History []string `json:"history"` // Direct history (preferred)
	}

	var req ValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var history []string

	if len(req.History) > 0 {
		history = req.History
	} else if req.Input != "" {
		history = strings.Fields(req.Input)
	} else {
		http.Error(w, "Missing input or history", http.StatusBadRequest)
		return
	}

	resp, err := h.runner.RunPDAValidation(history)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *PDAHandler) HandleGetGraph(w http.ResponseWriter, r *http.Request) {
	graph, err := h.runner.GetPDAGraph()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(graph)
}
