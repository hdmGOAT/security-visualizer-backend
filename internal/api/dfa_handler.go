package api

import (
	"encoding/json"
	"net/http"

	"security-backend/internal/models"
	"security-backend/internal/wrapper"
)

type DFAHandler struct {
	runner *wrapper.Runner
}

func NewDFAHandler(r *wrapper.Runner) *DFAHandler {
	return &DFAHandler{runner: r}
}

// HandleStep accepts POST { "packet": Packet }
func (h *DFAHandler) HandleStep(w http.ResponseWriter, r *http.Request) {
	type StepRequest struct {
		Packet models.Packet `json:"packet"`
	}

	var req StepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Determine start state dynamically from the graph JSON instead of
	// hardcoding a state like "s4". If we can't determine it, fall back
	// to the first node id or return an error.
	graph, gerr := h.runner.GetGraph()
	if gerr != nil {
		http.Error(w, gerr.Error(), http.StatusInternalServerError)
		return
	}

	startState := ""
	if graph != nil && len(graph.Nodes) > 0 {
		// Nodes are unmarshaled into interface{}; expect map[string]interface{}
		for _, raw := range graph.Nodes {
			if nodeMap, ok := raw.(map[string]interface{}); ok {
				if isStart, ok2 := nodeMap["is_start"].(bool); ok2 && isStart {
					if id, ok3 := nodeMap["id"].(string); ok3 {
						startState = id
						break
					}
				}
			}
		}
		// If no explicit start flag found, try the first node's id
		if startState == "" {
			if firstNode, ok := graph.Nodes[0].(map[string]interface{}); ok {
				if id, ok := firstNode["id"].(string); ok {
					startState = id
				}
			}
		}
	}

	if startState == "" {
		http.Error(w, "failed to determine start state for DFA", http.StatusInternalServerError)
		return
	}

	resp, err := h.runner.RunDFAStep(startState, req.Packet)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *DFAHandler) HandleGetGraph(w http.ResponseWriter, r *http.Request) {
	graph, err := h.runner.GetGraph()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(graph)
}

// Derivation now accepts POST { "packet": <Packet> }
func (h *DFAHandler) HandleGetDerivation(w http.ResponseWriter, r *http.Request) {
	type DeriveRequest struct {
		Packet models.Packet `json:"packet"`
	}

	var req DeriveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	steps, err := h.runner.RunDerivation(req.Packet)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"steps": steps,
	})
}

func (h *DFAHandler) HandleProcessRequest(w http.ResponseWriter, r *http.Request) {
	type RequestPayload struct {
		Packets   []models.Packet `json:"packets"`
		Threshold int             `json:"threshold"`
	}

	var req RequestPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Packets) == 0 {
		http.Error(w, "No packets provided", http.StatusBadRequest)
		return
	}

	// Default threshold to 1 if not provided
	threshold := req.Threshold
	if threshold <= 0 {
		threshold = 1
	}

	resp, err := h.runner.RunRequest(req.Packets, threshold)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
