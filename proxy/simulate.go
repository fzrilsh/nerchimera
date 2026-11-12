package main

import "net/http"

// Simulator serves POST /api/simulate. Task 11 replaces this placeholder with
// the fixed attack scenario runner and its rate limit.
type Simulator struct{}

func NewSimulator() *Simulator { return &Simulator{} }

func (s *Simulator) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "attack simulation is not implemented yet"})
}
