package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"ambassador/application/dto"
	"ambassador/domain/services"
	"ambassador/interfaces/http/middleware"
	"ambassador/interfaces/http/response"
)


type AuthHandler struct {
	authService services.AuthService
	validator   middleware.Validator
}

func NewAuthHandler(authService services.AuthService, validator middleware.Validator) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		validator:   validator,
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", r)
		return
	}

	var req dto.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", r)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error(), r)
		return
	}

	user, tokenPair, err := h.authService.Register(&req)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			response.Error(w, http.StatusConflict, "USER_ALREADY_EXISTS", err.Error(), r)
			return
		}
		response.Error(w, http.StatusBadRequest, "REGISTRATION_FAILED", err.Error(), r)
		return
	}

	authResponse := dto.ToAuthResponse(user, tokenPair)
	response.Success(w, http.StatusCreated, "User registered successfully", authResponse, r)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", r)
		return
	}

	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", r)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error(), r)
		return
	}

	tokenPair, err := h.authService.Login(&req)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid credentials", r)
		return
	}

	user, err := h.authService.GetProfile(tokenPair.AccessToken.Value)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get user profile", r)
		return
	}

	authResponse := dto.ToAuthResponse(user, tokenPair)
	response.Success(w, http.StatusOK, "Login successful", authResponse, r)
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", r)
		return
	}

	var req dto.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", r)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error(), r)
		return
	}

	tokenPair, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "INVALID_REFRESH_TOKEN", err.Error(), r)
		return
	}

	refreshResponse := dto.ToRefreshResponse(tokenPair)
	response.Success(w, http.StatusOK, "Token refreshed successfully", refreshResponse, r)
}

func (h *AuthHandler) Profile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		response.Error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", r)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		response.Error(w, http.StatusUnauthorized, "MISSING_TOKEN", "Authorization token required", r)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		response.Error(w, http.StatusUnauthorized, "INVALID_AUTH_FORMAT", "Invalid authorization format", r)
		return
	}

	user, err := h.authService.GetProfile(parts[1])
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "INVALID_TOKEN", err.Error(), r)
		return
	}

	userResponse := dto.ToUserResponse(user)
	response.Success(w, http.StatusOK, "Profile retrieved successfully", userResponse, r)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed", r)
		return
	}

	var req dto.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", r)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		response.Error(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error(), r)
		return
	}

	if err := h.authService.Logout(req.RefreshToken); err != nil {
		response.Error(w, http.StatusBadRequest, "LOGOUT_FAILED", err.Error(), r)
		return
	}

	response.Success(w, http.StatusOK, "Logout successful", nil, r)
}