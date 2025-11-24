package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"security-backend/internal/core"
	"security-backend/internal/wrapper"
)

type PDAHandler struct {
	sessionManager *core.SessionManager
	runner         *wrapper.Runner
}

func NewPDAHandler(sm *core.SessionManager, r *wrapper.Runner) *PDAHandler {
	return &PDAHandler{
		sessionManager: sm,
		runner:         r,
	}
}

func (h *PDAHandler) HandleValidate(w http.ResponseWriter, r *http.Request) {
	type ValidateRequest struct {
		SessionID string `json:"session_id"`
		HostID    string `json:"host_id"`
		Input     string `json:"input"` // Direct input for testing
	}

	var req ValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var history []string
	hostID := req.HostID

	if req.Input != "" {
		// Direct input mode
		// Split by space
		history = strings.Fields(req.Input)
		if hostID == "" {
			hostID = "manual-input"
		}
	} else {
		// Session mode
		session := h.sessionManager.GetSession(req.SessionID)
		if session == nil {
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}

		session.Mutex.RLock()
		h, exists := session.HostHistory[req.HostID]
		session.Mutex.RUnlock()

		if !exists || len(h) == 0 {
			http.Error(w, "No history for host", http.StatusNotFound)
			return
		}
		history = h
	}

	resp, err := h.runner.RunPDAValidation(hostID, history)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
