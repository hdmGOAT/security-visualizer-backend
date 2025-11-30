package wrapper

import (
    "fmt"

    "security-backend/internal/models"
)

// RunRequest processes a high-level request composed of multiple packets.
// It will:
// - Build a PDA history (sequence of terminals) from the packets and run the PDA validator
// - For each packet, run the DFA step(s) starting from the start state (stateless per-packet)
// Returns combined result including PDA response and per-packet DFA responses
func (r *Runner) RunRequest(packets []models.Packet, threshold int) (*models.RequestProcessingResponse, error) {
    // Build PDA history: expand each packet to the sequence [proto=..., service=..., state=...]
    var history []string
    for _, p := range packets {
        if p.Proto != "" && p.Proto != "-" {
            history = append(history, "proto="+p.Proto)
        }
        if p.Service != "" && p.Service != "-" {
            history = append(history, "service="+p.Service)
        }
        if p.ConnState != "" && p.ConnState != "-" {
            history = append(history, "state="+p.ConnState)
        }
    }

    pdaResp, err := r.RunPDAValidation(history)
    if err != nil {
        return nil, err
    }

    // For per-packet DFA processing, we run each packet starting from the start state `s4`.
    var packetResults []models.DFAPacketResponse
    for _, p := range packets {
        dres, err := r.RunDFAStep("s4", p)
        if err != nil {
            // On error, include a simple error-like DFAPacketResponse
            packetResults = append(packetResults, models.DFAPacketResponse{
                Steps:       []models.DFAStep{},
                FinalState:  "error",
                IsMalicious: false,
                Label:       fmt.Sprintf("error: %v", err),
            })
            continue
        }
        packetResults = append(packetResults, *dres)
    }

    // Decide whether the whole request is malicious based on the provided threshold.
    maliciousCount := 0
    for _, pr := range packetResults {
        if pr.IsMalicious {
            maliciousCount++
        }
    }

    overallMalicious := false
    if threshold > 0 && maliciousCount >= threshold {
        overallMalicious = true
    }

    return &models.RequestProcessingResponse{
        PDA:         *pdaResp,
        Packets:     packetResults,
        IsMalicious: overallMalicious,
    }, nil
}
