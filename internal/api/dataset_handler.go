package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"security-backend/internal/wrapper"
)

type DatasetHandler struct {
	runner *wrapper.Runner
}

func NewDatasetHandler(r *wrapper.Runner) *DatasetHandler {
	return &DatasetHandler{runner: r}
}

type Dataset struct {
	Name  string   `json:"name"`
	Files []string `json:"files"`
}

func (h *DatasetHandler) HandleListDatasets(w http.ResponseWriter, r *http.Request) {
	datasetsDir := "datasets"
	var datasets []Dataset

	// Walk through datasets directory
	// Structure: datasets/<folder>/<file>.csv
	// Or just datasets/<file>.csv?
	// The user copied `security-dfa-gen/datasets` which has `iotMalware/*.csv`.

	// Let's support nested structure.
	err := filepath.Walk(datasetsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".csv") {
			relPath, _ := filepath.Rel(datasetsDir, path)
			datasets = append(datasets, Dataset{
				Name:  relPath,
				Files: []string{relPath},
			})
		}
		return nil
	})

	if err != nil {
		// If datasets dir doesn't exist, return empty list
		datasets = []Dataset{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(datasets)
}

type LoadDatasetRequest struct {
	Filename string `json:"filename"`
}

func (h *DatasetHandler) HandleLoadDataset(w http.ResponseWriter, r *http.Request) {
	var req LoadDatasetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	datasetPath := filepath.Join("datasets", req.Filename)
	absPath, err := filepath.Abs(datasetPath)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Run generator
	dotPath, grammarPath, output, err := h.runner.GenerateFromDataset(absPath)
	if err != nil {
		http.Error(w, "Generation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update runner paths
	// Note: We only update DFA paths. PDA paths remain default unless we have a way to generate PDA.
	h.runner.SetPaths(dotPath, grammarPath, "", "")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "loaded",
		"dot":     dotPath,
		"grammar": grammarPath,
		"output":  output,
	})
}
