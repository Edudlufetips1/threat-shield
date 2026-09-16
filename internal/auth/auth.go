package auth

import (
	"crypto/subtle"
	"net/http"
	"os"
)

func RequireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedAPIKey := os.Getenv("API_KEY")
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, "API key required", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(apiKey), []byte(expectedAPIKey)) != 1 {
			http.Error(w, "Invalid API key", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
