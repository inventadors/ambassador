package auth

import (
	"ambassador/internal/shared/middleware"
	"ambassador/internal/shared/response"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	service   *AuthService
	validator middleware.Validator
}

func NewAuthHandler(service *AuthService, validator middleware.Validator) *AuthHandler {
	return &AuthHandler{
		service:   service,
		validator: validator,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	if err := h.validator.Validate(req); err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	user, tokenPair, err := h.service.Register(&req)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			response.Error(c, http.StatusConflict, "USER_ALREADY_EXISTS", err.Error())
			return
		}
		response.Error(c, http.StatusBadRequest, "REGISTRATION_FAILED", err.Error())
		return
	}

	authResponse := ToAuthResponse(user, tokenPair)
	response.Success(c, http.StatusCreated, "User registered successfully", authResponse)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	if err := h.validator.Validate(req); err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	tokenPair, err := h.service.Login(&req)
	if err != nil {
		response.Error(c, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid credentials")
		return
	}

	user, err := h.service.GetProfile(tokenPair.AccessToken.Value)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get user profile")
		return
	}

	authResponse := ToAuthResponse(user, tokenPair)
	response.Success(c, http.StatusOK, "Login successful", authResponse)
}

func (h *AuthHandler) Profile(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		response.Error(c, http.StatusUnauthorized, "MISSING_TOKEN", "Authorization token required")
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		response.Error(c, http.StatusUnauthorized, "INVALID_AUTH_FORMAT", "Invalid authorization format")
		return
	}

	user, err := h.service.GetProfile(parts[1])
	if err != nil {
		response.Error(c, http.StatusUnauthorized, "INVALID_TOKEN", err.Error())
		return
	}

	userResponse := ToUserResponse(user)
	response.Success(c, http.StatusOK, "Profile retrieved successfully", userResponse)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	if err := h.validator.Validate(req); err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	if err := h.service.Logout(req.RefreshToken); err != nil {
		response.Error(c, http.StatusBadRequest, "LOGOUT_FAILED", err.Error())
		return
	}

	response.Success(c, http.StatusOK, "Logout successful", nil)
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	if err := h.validator.Validate(req); err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	tokenPair, err := h.service.RefreshToken(req.RefreshToken)
	if err != nil {
		response.Error(c, http.StatusUnauthorized, "INVALID_REFRESH_TOKEN", err.Error())
		return
	}

	refreshResponse := ToRefreshResponse(tokenPair)
	response.Success(c, http.StatusOK, "Token refreshed successfully", refreshResponse)
}