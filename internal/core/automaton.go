package core

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"security-backend/internal/models"
)

type Automaton struct {
	Nodes       map[string]*Node
	Edges       []*Edge
	StartNode   string
	Transitions map[string]map[string]string // state -> symbol -> next_state
	Grammar     *Grammar
	mutex       sync.RWMutex
}

type Node struct {
	ID          string
	Label       string
	IsAccepting bool
	IsStart     bool
}

type Edge struct {
	Source string
	Target string
	Label  string
}

type Grammar struct {
	Productions map[string][]Production
	Terminals   map[string]string // T0 -> proto=icmp
}

type Production struct {
	LHS string
	RHS []string // e.g. ["T0", "A3"] or ["service=http"]
}

func NewAutomaton() *Automaton {
	return &Automaton{
		Nodes:       make(map[string]*Node),
		Transitions: make(map[string]map[string]string),
	}
}

func (a *Automaton) LoadFromDOT(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	
	// Regex patterns
	nodePattern := regexp.MustCompile(`^\s*(\w+)\s*\[label="([^"]+)"(.*)\];`)
	edgePattern := regexp.MustCompile(`^\s*(\w+)\s*->\s*(\w+)\s*\[label="([^"]+)"\];`)
	startPattern := regexp.MustCompile(`^\s*__start\s*->\s*(\w+);`)

	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Reset
	a.Nodes = make(map[string]*Node)
	a.Edges = make([]*Edge, 0)
	a.Transitions = make(map[string]map[string]string)

	for scanner.Scan() {
		line := scanner.Text()
		
		if matches := startPattern.FindStringSubmatch(line); len(matches) > 1 {
			a.StartNode = matches[1]
			continue
		}

		if matches := nodePattern.FindStringSubmatch(line); len(matches) > 1 {
			id := matches[1]
			if id == "__start" {
				continue
			}
			label := matches[2]
			attrs := matches[3]
			isAccepting := strings.Contains(attrs, "doublecircle")
			
			a.Nodes[id] = &Node{
				ID:          id,
				Label:       strings.Split(label, "\\n")[0], // Clean label
				IsAccepting: isAccepting,
			}
		}

		if matches := edgePattern.FindStringSubmatch(line); len(matches) > 1 {
			source := matches[1]
			target := matches[2]
			label := matches[3]

			if source == "__start" {
				continue
			}

			a.Edges = append(a.Edges, &Edge{
				Source: source,
				Target: target,
				Label:  label,
			})

			if _, exists := a.Transitions[source]; !exists {
				a.Transitions[source] = make(map[string]string)
			}
			a.Transitions[source][label] = target
		}
	}

	// Mark start node
	if startNode, exists := a.Nodes[a.StartNode]; exists {
		startNode.IsStart = true
	}

	return scanner.Err()
}

func (a *Automaton) LoadGrammar(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	a.Grammar = &Grammar{
		Productions: make(map[string][]Production),
		Terminals:   make(map[string]string),
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse Terminals: T0 -> proto=icmp
		if strings.HasPrefix(line, "T") && strings.Contains(line, "->") && !strings.Contains(line, "|") {
			parts := strings.Split(line, "->")
			lhs := strings.TrimSpace(parts[0])
			rhs := strings.TrimSpace(parts[1])
			a.Grammar.Terminals[lhs] = rhs
			continue
		}

		// Parse Productions: S -> T0 A3 | ...
		if strings.Contains(line, "->") {
			parts := strings.Split(line, "->")
			lhs := strings.TrimSpace(parts[0])
			rhs := strings.TrimSpace(parts[1])

			alts := strings.Split(rhs, "|")
			for _, alt := range alts {
				alt = strings.TrimSpace(alt)
				tokens := strings.Fields(alt)
				a.Grammar.Productions[lhs] = append(a.Grammar.Productions[lhs], Production{
					LHS: lhs,
					RHS: tokens,
				})
			}
		}
	}
	return scanner.Err()
}

func (a *Automaton) GetGraph() models.GraphResponse {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	resp := models.GraphResponse{
		Nodes: make([]interface{}, 0, len(a.Nodes)),
		Edges: make([]interface{}, 0, len(a.Edges)),
	}

	for _, n := range a.Nodes {
		resp.Nodes = append(resp.Nodes, map[string]interface{}{
			"id":           n.ID,
			"label":        n.Label,
			"is_accepting": n.IsAccepting,
			"is_start":     n.IsStart,
		})
	}

	for _, e := range a.Edges {
		resp.Edges = append(resp.Edges, map[string]interface{}{
			"source": e.Source,
			"target": e.Target,
			"label":  e.Label,
		})
	}

	return resp
}

func (a *Automaton) Step(currentState string, packet models.Packet) (string, bool, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	// Sequence of symbols to process
	symbols := []string{
		"proto=" + packet.Proto,
		"service=" + packet.Service,
		"state=" + packet.ConnState,
	}

	curr := currentState
	// If current state is empty or invalid, reset to start
	if _, exists := a.Nodes[curr]; !exists {
		curr = a.StartNode
	}

	for _, sym := range symbols {
		if next, ok := a.Transitions[curr][sym]; ok {
			curr = next
		} else {
			// If no transition, we might be in a sink state or invalid path
			// For now, stay in current state or return error?
			// The DOT file has a sink state s5 (A3) which loops.
			// If we are in a state that doesn't have a transition, it's effectively a rejection/stuck.
			// But let's see if we can find a transition.
			return curr, false, fmt.Errorf("no transition for symbol %s from state %s", sym, curr)
		}
	}

	isMalicious := false
	if node, ok := a.Nodes[curr]; ok {
		isMalicious = node.IsAccepting
	}

	return curr, isMalicious, nil
}

func (a *Automaton) GetDerivation(history []models.Packet) ([]string, error) {
	// This is a simplified derivation reconstruction.
	// We assume the grammar is regular and deterministic enough for the trace.
	// We start at S.
	
	if a.Grammar == nil {
		return nil, fmt.Errorf("grammar not loaded")
	}

	derivation := []string{"S"}
	currentNonTerminal := "S"
	
	// Flatten history into symbols
	var symbols []string
	for _, p := range history {
		symbols = append(symbols, "proto="+p.Proto)
		symbols = append(symbols, "service="+p.Service)
		symbols = append(symbols, "state="+p.ConnState)
	}

	currentString := ""

	for _, sym := range symbols {
		// Find production from currentNonTerminal that matches sym
		// Production looks like: A -> Tn B  or A -> terminal
		// We need to find the one where Tn matches sym or terminal matches sym
		
		found := false
		for _, prod := range a.Grammar.Productions[currentNonTerminal] {
			// Check if first token matches symbol
			firstToken := prod.RHS[0]
			
			match := false
			if strings.HasPrefix(firstToken, "T") {
				if val, ok := a.Grammar.Terminals[firstToken]; ok && val == sym {
					match = true
				}
			} else if firstToken == sym {
				match = true
			}

			if match {
				// Found the production
				// Update derivation string
				// Replace currentNonTerminal with RHS
				
				// Construct the new string part
				rhsStr := ""
				nextNonTerminal := ""
				
				for _, token := range prod.RHS {
					if strings.HasPrefix(token, "T") {
						rhsStr += a.Grammar.Terminals[token] + " "
					} else if val, ok := a.Grammar.Productions[token]; ok {
						// It's a non-terminal (heuristic check)
						// Actually we should check if it's in the Nonterminals set, but checking if it has productions is a good proxy
						_ = val
						nextNonTerminal = token
						rhsStr += token + " "
					} else {
						// Literal terminal
						rhsStr += token + " "
					}
				}
				
				// Update the full derivation string
				// The current string is "processed_symbols currentNonTerminal"
				// We want "processed_symbols rhsStr"
				
				step := strings.TrimSpace(currentString + " " + rhsStr)
				derivation = append(derivation, step)
				
				currentString += " " + sym
				currentNonTerminal = nextNonTerminal
				found = true
				break
			}
		}
		
		if !found {
			// If we can't derive, stop
			break
		}
		
		if currentNonTerminal == "" {
			// Reached a terminal production (end of derivation?)
			break
		}
	}

	return derivation, nil
}
