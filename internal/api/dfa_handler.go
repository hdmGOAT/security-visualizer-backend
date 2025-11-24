package api

import (
	"encoding/json"
	"net/http"

	"security-backend/internal/core"
	"security-backend/internal/models"
	"security-backend/internal/wrapper"
)

type DFAHandler struct {
	sessionManager *core.SessionManager
	runner         *wrapper.Runner
}

func NewDFAHandler(sm *core.SessionManager, r *wrapper.Runner) *DFAHandler {
	return &DFAHandler{
		sessionManager: sm,
		runner:         r,
	}
}

func (h *DFAHandler) HandleStep(w http.ResponseWriter, r *http.Request) {
	type StepRequest struct {
		SessionID string        `json:"session_id"`
		Packet    models.Packet `json:"packet"`
	}

	var req StepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	session := h.sessionManager.GetSession(req.SessionID)
	if session == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Run C++ DFA Step
	// We use the session's current state and the new packet
	// User requested to always start from initial state for each packet
	resp, err := h.runner.RunDFAStep("s4", req.Packet)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update Session State
	session.AddPacket(req.Packet)
	session.UpdateState(resp.FinalState)

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

func (h *DFAHandler) HandleGetDerivation(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing session_id", http.StatusBadRequest)
		return
	}

	session := h.sessionManager.GetSession(sessionID)
	if session == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	if len(session.History) == 0 {
		http.Error(w, "No packets in history", http.StatusBadRequest)
		return
	}

	// Run derivation for the last packet
	lastPacket := session.History[len(session.History)-1]
	steps, err := h.runner.RunDerivation(lastPacket)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"steps": steps,
	})
}
