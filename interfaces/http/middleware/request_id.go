// interfaces/http/middleware/request_id.go
package middleware

import (
	"context"
	"net/http"
	"github.com/google/uuid"
)

func RequestID(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		
		ctx := context.WithValue(r.Context(), "requestID", requestID)
		w.Header().Set("X-Request-ID", requestID)
		
		next(w, r.WithContext(ctx))
	}
}