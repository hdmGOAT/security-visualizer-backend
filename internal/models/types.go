package models

// Packet represents the input packet structure from the frontend
type Packet struct {
	Proto     string `json:"proto"`      // e.g., "tcp"
	Service   string `json:"service"`    // e.g., "http"
	ConnState string `json:"conn_state"` // e.g., "S0", "SF"
	HostID    string `json:"host_id"`    // e.g., "192.168.1.5"
}

// DFAStep represents a single transition in the DFA
type DFAStep struct {
	CurrentState string `json:"current_state"`
	Symbol       string `json:"symbol"`
	NextState    string `json:"next_state"`
}

// DFAPacketResponse represents the response for processing a packet
type DFAPacketResponse struct {
	Steps       []DFAStep `json:"steps"`
	FinalState  string    `json:"final_state"`
	IsMalicious bool      `json:"is_malicious"`
	Label       string    `json:"label"`
}

// StackOperation represents a single operation on the PDA stack
type StackOperation struct {
	StepIndex int      `json:"step_index"`
	Action    string   `json:"action"`     // "PUSH", "POP", "NO_OP"
	Symbol    string   `json:"symbol"`     // The symbol pushed/popped (e.g., "S0")
	Stack     []string `json:"stack"`      // Snapshot of stack after op: ["S0", "S1"]
}

// PDAValidationResponse represents the result of a PDA validation
type PDAValidationResponse struct {
	HostID  string           `json:"host_id"`
	IsValid bool             `json:"is_valid"`
	Trace   []StackOperation `json:"trace"`
}

// SessionInitResponse represents the response when starting a session
type SessionInitResponse struct {
	SessionID string `json:"session_id"`
}

// GraphResponse represents the static graph structure
type GraphResponse struct {
	Nodes []interface{} `json:"nodes"` // React Flow nodes
	Edges []interface{} `json:"edges"` // React Flow edges
}
