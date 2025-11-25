package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"security-backend/internal/api"
	"security-backend/internal/core"
	"security-backend/internal/models"
	"security-backend/internal/wrapper"
)

func main() {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // Adjust for production
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Core Components
	sessionManager := core.NewSessionManager()
	runner := wrapper.NewRunner()

	// Handlers
	dfaHandler := api.NewDFAHandler(sessionManager, runner)
	pdaHandler := api.NewPDAHandler(sessionManager, runner)

	// Routes
	r.Post("/api/session", func(w http.ResponseWriter, r *http.Request) {
		session := sessionManager.CreateSession()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.SessionInitResponse{SessionID: session.ID})
	})

	r.Post("/api/dfa/step", dfaHandler.HandleStep)
	r.Get("/api/graph", dfaHandler.HandleGetGraph)
	r.Get("/api/derivation", dfaHandler.HandleGetDerivation)
	r.Post("/api/request/process", dfaHandler.HandleProcessRequest)
	r.Get("/api/pda/graph", pdaHandler.HandleGetGraph)
	r.Post("/api/pda/validate", pdaHandler.HandleValidate)

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
