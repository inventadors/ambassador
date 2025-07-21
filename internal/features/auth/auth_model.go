package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
)

type Gender string
type RegistrationMethod string
type TokenType string

const (
	GenderMale           Gender = "male"
	GenderFemale         Gender = "female"
	GenderOther          Gender = "other"
	GenderPreferNotToSay Gender = "prefer_not_to_say"

	RegMethodEmail  RegistrationMethod = "email"
	RegMethodGoogle RegistrationMethod = "google"
	RegMethodApple  RegistrationMethod = "apple"

	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

type Email struct {
	value string
}

func NewEmail(email string) (*Email, error) {
	cleaned := strings.ToLower(strings.TrimSpace(email))
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	if !emailRegex.MatchString(cleaned) {
		return nil, errors.New("invalid email format")
	}

	return &Email{value: cleaned}, nil
}

func (e *Email) String() string {
	return e.value
}

type User struct {
	ID                 string             `json:"id"`
	Email              *Email             `json:"email"`
	FullName           string             `json:"full_name"`
	Gender             Gender             `json:"gender"`
	DateOfBirth        time.Time          `json:"date_of_birth"`
	RegistrationMethod RegistrationMethod `json:"registration_method"`
	PasswordHash       string             `json:"-"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
	IsActive           bool               `json:"is_active"`
}

func NewUser(email, fullName string, gender Gender, dateOfBirth time.Time, regMethod RegistrationMethod, passwordHash string) (*User, error) {
	emailVO, err := NewEmail(email)
	if err != nil {
		return nil, err
	}

	cleanedFullName := strings.TrimSpace(fullName)
	if cleanedFullName == "" {
		return nil, errors.New("full name is required")
	}
	nameRegex := regexp.MustCompile(`^[a-zA-Z\s\-\']+$`)
	if !nameRegex.MatchString(cleanedFullName) {
		return nil, errors.New("full name contains invalid characters")
	}

	now := time.Now()
	return &User{
		Email:              emailVO,
		FullName:           cleanedFullName,
		Gender:             gender,
		DateOfBirth:        dateOfBirth,
		RegistrationMethod: regMethod,
		PasswordHash:       passwordHash,
		CreatedAt:          now,
		UpdatedAt:          now,
		IsActive:           true,
	}, nil
}

type Token struct {
	Value     string    `json:"token"`
	UserID    string    `json:"userId"`
	Type      TokenType `json:"type"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

func NewAccessToken(userID string) *Token {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	tokenValue := hex.EncodeToString(tokenBytes)

	return &Token{
		Value:     tokenValue,
		UserID:    userID,
		Type:      TokenTypeAccess,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		CreatedAt: time.Now(),
	}
}

func NewRefreshToken(userID string) *Token {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	tokenValue := hex.EncodeToString(tokenBytes)

	return &Token{
		Value:     tokenValue,
		UserID:    userID,
		Type:      TokenTypeRefresh,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}
}

func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

type TokenPair struct {
	AccessToken  *Token `json:"accessToken"`
	RefreshToken *Token `json:"refreshToken"`
}

func NewTokenPair(userID string) *TokenPair {
	return &TokenPair{
		AccessToken:  NewAccessToken(userID),
		RefreshToken: NewRefreshToken(userID),
	}
}