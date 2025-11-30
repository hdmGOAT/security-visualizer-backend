package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"security-backend/internal/api"
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
	runner := wrapper.NewRunner()

	// Handlers (stateless)
	dfaHandler := api.NewDFAHandler(runner)
	pdaHandler := api.NewPDAHandler(runner)

	// Routes
	r.Post("/api/dfa/step", dfaHandler.HandleStep)
	r.Get("/api/graph", dfaHandler.HandleGetGraph)
	// Derivation now accepts a POST body with the packet to derive
	r.Post("/api/derivation", dfaHandler.HandleGetDerivation)
	r.Post("/api/request/process", dfaHandler.HandleProcessRequest)
	r.Get("/api/pda/graph", pdaHandler.HandleGetGraph)
	r.Post("/api/pda/validate", pdaHandler.HandleValidate)

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
