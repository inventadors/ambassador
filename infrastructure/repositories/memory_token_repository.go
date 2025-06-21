package repositories

import (
	"errors"
	"sync"
	"time"
	"ambassador/domain/entities"
	"ambassador/domain/repositories"
)


type MemoryTokenRepository struct {
	tokens map[string]*entities.Token
	mu     sync.RWMutex
}

func NewMemoryTokenRepository() repositories.TokenRepository {
	return &MemoryTokenRepository{
		tokens: make(map[string]*entities.Token),
	}
}

func (r *MemoryTokenRepository) Save(token *entities.Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[token.Value] = token
	return nil
}

func (r *MemoryTokenRepository) FindByValue(value string) (*entities.Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	token, exists := r.tokens[value]
	if !exists {
		return nil, errors.New("token not found")
	}
	return token, nil
}

func (r *MemoryTokenRepository) Delete(value string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tokens, value)
	return nil
}

func (r *MemoryTokenRepository) DeleteExpired() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for value, token := range r.tokens {
		if token.ExpiresAt.Before(now) {
			delete(r.tokens, value)
		}
	}
	return nil
}

func (r *MemoryTokenRepository) DeleteAllUserTokens(userID string, tokenType entities.TokenType) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for value, token := range r.tokens {
		if token.UserID == userID && token.Type == tokenType {
			delete(r.tokens, value)
		}
	}
	return nil
}

func (r *MemoryTokenRepository) FindByUserID(userID string, tokenType entities.TokenType) ([]*entities.Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var tokens []*entities.Token
	for _, token := range r.tokens {
		if token.UserID == userID && token.Type == tokenType {
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}