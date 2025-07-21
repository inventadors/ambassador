package response

import (
	"time"
	"github.com/gin-gonic/gin"
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

func Success(c *gin.Context, status int, message string, data interface{}) {
	sendResponse(c, true, status, "", message, data)
}

func Error(c *gin.Context, status int, code, message string) {
	sendResponse(c, false, status, code, message, nil)
}

func sendResponse(c *gin.Context, success bool, status int, code, message string, data interface{}) {
	requestID, _ := c.Get("requestID")
	res := APIResponse{
		Success:        success,
		HTTPStatusCode: status,
		ErrorCode:      code,
		Message:        message,
		Data:           data,
		Meta: Meta{
			RequestID:  requestID.(string),
			Timestamp:  time.Now().UTC(),
			APIVersion: "1.0",
		},
	}
	c.JSON(status, res)
}