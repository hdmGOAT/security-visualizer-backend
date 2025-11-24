package core

import (
	"sync"

	"github.com/google/uuid"
	"security-backend/internal/models"
)

// Session holds the state for a user's interaction
type Session struct {
	ID           string
	CurrentState string
	History      []models.Packet
	HostHistory  map[string][]string // HostID -> Sequence of ConnStates
	Mutex        sync.RWMutex
}

// SessionManager manages active sessions
type SessionManager struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
}

// NewSessionManager creates a new SessionManager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
	}
}

// CreateSession initializes a new session
func (sm *SessionManager) CreateSession() *Session {
	id := uuid.New().String()
	session := &Session{
		ID:           id,
		CurrentState: "s4", // Start state from automaton.dot
		History:      make([]models.Packet, 0),
		HostHistory:  make(map[string][]string),
	}

	sm.mutex.Lock()
	sm.sessions[id] = session
	sm.mutex.Unlock()

	return session
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(id string) *Session {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return sm.sessions[id]
}

// AddPacket updates the session with a new packet
func (s *Session) AddPacket(p models.Packet) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.History = append(s.History, p)
	
	// Update host-specific history for PDA
	if _, exists := s.HostHistory[p.HostID]; !exists {
		s.HostHistory[p.HostID] = []string{}
	}
	// We only care about ConnState for PDA as per spec
	// Format: "state=S0"
	s.HostHistory[p.HostID] = append(s.HostHistory[p.HostID], "state="+p.ConnState)
}

// UpdateState updates the current DFA state
func (s *Session) UpdateState(newState string) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.CurrentState = newState
}
