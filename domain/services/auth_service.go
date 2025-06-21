package services

import (
	"ambassador/application/dto"
	"ambassador/domain/entities"
)

type AuthService interface {
	Register(req *dto.RegisterRequest) (*entities.User, *entities.TokenPair, error)
	Login(req *dto.LoginRequest) (*entities.TokenPair, error)
	RefreshToken(refreshToken string) (*entities.TokenPair, error)
	GetProfile(accessToken string) (*entities.User, error)
	Logout(refreshToken string) error
}