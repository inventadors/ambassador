package auth

import (
	"errors"
	"sync"
	"time"
)

type UserRepository interface {
	Save(user *User) error
	FindByEmail(email string) (*User, error)
	FindByID(id string) (*User, error)
	ExistsByEmail(email string) (bool, error)
}

type TokenRepository interface {
	Save(token *Token) error
	FindByValue(value string) (*Token, error)
	Delete(value string) error
	DeleteExpired() error
	DeleteAllUserTokens(userID string, tokenType TokenType) error
	FindByUserID(userID string, tokenType TokenType) ([]*Token, error)
}

// Memory implementations
type MemoryUserRepository struct {
	users map[string]*User
	mu    sync.RWMutex
}

func NewMemoryUserRepository() UserRepository {
	return &MemoryUserRepository{
		users: make(map[string]*User),
	}
}

func (r *MemoryUserRepository) Save(user *User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[user.ID] = user
	return nil
}

func (r *MemoryUserRepository) FindByEmail(email string) (*User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user.Email.String() == email {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (r *MemoryUserRepository) FindByID(id string) (*User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, exists := r.users[id]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (r *MemoryUserRepository) ExistsByEmail(email string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user.Email.String() == email {
			return true, nil
		}
	}
	return false, nil
}

type MemoryTokenRepository struct {
	tokens map[string]*Token
	mu     sync.RWMutex
}

func NewMemoryTokenRepository() TokenRepository {
	return &MemoryTokenRepository{
		tokens: make(map[string]*Token),
	}
}

func (r *MemoryTokenRepository) Save(token *Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[token.Value] = token
	return nil
}

func (r *MemoryTokenRepository) FindByValue(value string) (*Token, error) {
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

func (r *MemoryTokenRepository) DeleteAllUserTokens(userID string, tokenType TokenType) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for value, token := range r.tokens {
		if token.UserID == userID && token.Type == tokenType {
			delete(r.tokens, value)
		}
	}
	return nil
}

func (r *MemoryTokenRepository) FindByUserID(userID string, tokenType TokenType) ([]*Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var tokens []*Token
	for _, token := range r.tokens {
		if token.UserID == userID && token.Type == tokenType {
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}