package handlers

import (
	"encoding/json"
	"net/http"
	"time"
)

// Health returns a simple status response.
func Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"service": "resource-server",
		"time":    time.Now().Unix(),
	})
}
