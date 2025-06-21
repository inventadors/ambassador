package repositories

import "ambassador/domain/entities"

type TokenRepository interface {
	Save(token *entities.Token) error
	FindByValue(value string) (*entities.Token, error)
	Delete(value string) error
	DeleteExpired() error
	DeleteAllUserTokens(userID string, tokenType entities.TokenType) error
	FindByUserID(userID string, tokenType entities.TokenType) ([]*entities.Token, error)
}