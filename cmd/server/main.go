package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"security-backend/internal/api"
	"security-backend/internal/wrapper"
)

func main() {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Manual CORS to ensure headers are always present
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token, ngrok-skip-browser-warning")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// Core Components
	runner := wrapper.NewRunner()

	// Handlers (stateless)
	dfaHandler := api.NewDFAHandler(runner)
	pdaHandler := api.NewPDAHandler(runner)
	configHandler := api.NewConfigHandler(runner)
	datasetHandler := api.NewDatasetHandler(runner)

	// Routes
	r.Post("/api/dfa/step", dfaHandler.HandleStep)
	r.Get("/api/graph", dfaHandler.HandleGetGraph)
	r.Get("/api/grammar", dfaHandler.HandleGetGrammar)
	// Derivation now accepts a POST body with the packet to derive
	r.Post("/api/derivation", dfaHandler.HandleGetDerivation)
	r.Post("/api/request/process", dfaHandler.HandleProcessRequest)
	r.Get("/api/pda/graph", pdaHandler.HandleGetGraph)
	r.Post("/api/pda/derivation", pdaHandler.HandleGetDerivation)
	r.Get("/api/pda/grammar", pdaHandler.HandleGetGrammar)
	r.Post("/api/pda/validate", pdaHandler.HandleValidate)

	// Config routes
	r.Post("/api/config/upload", configHandler.HandleUploadConfig)
	r.Post("/api/config/reset", configHandler.HandleResetConfig)

	// Dataset routes
	r.Get("/api/datasets", datasetHandler.HandleListDatasets)
	r.Post("/api/datasets/load", datasetHandler.HandleLoadDataset)

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
