

// interfaces/http/response/response.go
package response

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
	"github.com/google/uuid"
)

type APIResponse struct {
	Success        bool        `json:"success"`
	HTTPStatusCode int         `json:"httpStatusCode"`
	ErrorCode      string      `json:"errorCode,omitempty"`
	Message        string      `json:"message"`
	Data           interface{} `json:"data,omitempty"`
	Meta           Meta        `json:"meta"`
}

type Meta struct {
	RequestID  string    `json:"requestId"`
	Timestamp  time.Time `json:"timestamp"`
	APIVersion string    `json:"apiVersion"`
	RetryAfter int       `json:"retryAfter,omitempty"`
}

func Success(w http.ResponseWriter, status int, message string, data interface{}, r *http.Request) {
	sendResponse(w, true, status, "", message, data, getRequestID(r))
}

func Error(w http.ResponseWriter, status int, code, message string, r *http.Request) {
	sendResponse(w, false, status, code, message, nil, getRequestID(r))
}

func sendResponse(w http.ResponseWriter, success bool, status int, code, message string, data interface{}, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	
	res := APIResponse{
		Success:        success,
		HTTPStatusCode: status,
		ErrorCode:      code,
		Message:        message,
		Data:           data,
		Meta: Meta{
			RequestID:  requestID,
			Timestamp:  time.Now().UTC(),
			APIVersion: "1.0",
		},
	}
	
	if err := json.NewEncoder(w).Encode(res); err != nil {
		log.Printf("JSON encode error: %v", err)
	}
}

func getRequestID(r *http.Request) string {
	if id := r.Context().Value("requestID"); id != nil {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return uuid.New().String()
}