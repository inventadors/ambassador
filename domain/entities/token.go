package entities

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

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