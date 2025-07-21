package auth

import (
	"ambassador/internal/shared/security"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

type AuthService struct {
	userRepo  UserRepository
	tokenRepo TokenRepository
	hasher    security.PasswordHasher
}

func NewAuthService(userRepo UserRepository, tokenRepo TokenRepository, hasher security.PasswordHasher) *AuthService {
	return &AuthService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		hasher:    hasher,
	}
}

func (s *AuthService) Register(req *RegisterRequest) (*User, *TokenPair, error) {
	exists, err := s.userRepo.ExistsByEmail(req.Email)
	if err != nil {
		return nil, nil, err
	}
	if exists {
		return nil, nil, errors.New("user already exists")
	}

	dob, err := time.Parse("2006-01-02", req.DateOfBirth)
	if err != nil {
		return nil, nil, errors.New("invalid date of birth format")
	}

	if err := s.validateDateOfBirth(req.DateOfBirth); err != nil {
		return nil, nil, err
	}

	var passwordHash string
	if req.RegistrationMethod == RegMethodEmail {
		if strings.TrimSpace(req.Password) == "" {
			return nil, nil, errors.New("password is required for email registration")
		}
		if err := s.validatePassword(req.Password); err != nil {
			return nil, nil, err
		}
		passwordHash, err = s.hasher.HashPassword(req.Password)
		if err != nil {
			return nil, nil, err
		}
	} else if req.Password != "" {
		return nil, nil, errors.New("password should not be provided for OAuth registration")
	}

	user, err := NewUser(
		req.Email,
		req.FullName,
		req.Gender,
		dob,
		req.RegistrationMethod,
		passwordHash,
	)
	if err != nil {
		return nil, nil, err
	}

	user.ID = uuid.New().String()

	if err := s.userRepo.Save(user); err != nil {
		return nil, nil, err
	}

	tokenPair := NewTokenPair(user.ID)

	if err := s.tokenRepo.Save(tokenPair.AccessToken); err != nil {
		return nil, nil, err
	}
	if err := s.tokenRepo.Save(tokenPair.RefreshToken); err != nil {
		return nil, nil, err
	}

	return user, tokenPair, nil
}

func (s *AuthService) Login(req *LoginRequest) (*TokenPair, error) {
	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	if user.RegistrationMethod != RegMethodEmail {
		return nil, errors.New("please use OAuth login method")
	}

	if !s.hasher.CheckPassword(req.Password, user.PasswordHash) {
		return nil, errors.New("invalid credentials")
	}

	s.tokenRepo.DeleteAllUserTokens(user.ID, TokenTypeRefresh)

	tokenPair := NewTokenPair(user.ID)

	if err := s.tokenRepo.Save(tokenPair.AccessToken); err != nil {
		return nil, err
	}
	if err := s.tokenRepo.Save(tokenPair.RefreshToken); err != nil {
		return nil, err
	}

	return tokenPair, nil
}

func (s *AuthService) RefreshToken(refreshTokenValue string) (*TokenPair, error) {
	refreshToken, err := s.tokenRepo.FindByValue(refreshTokenValue)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	if refreshToken.Type != TokenTypeRefresh {
		return nil, errors.New("invalid token type")
	}

	if refreshToken.IsExpired() {
		s.tokenRepo.Delete(refreshTokenValue)
		return nil, errors.New("refresh token expired")
	}

	user, err := s.userRepo.FindByID(refreshToken.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	newTokenPair := NewTokenPair(user.ID)

	if err := s.tokenRepo.Save(newTokenPair.AccessToken); err != nil {
		return nil, err
	}
	if err := s.tokenRepo.Save(newTokenPair.RefreshToken); err != nil {
		return nil, err
	}

	s.tokenRepo.Delete(refreshTokenValue)

	return newTokenPair, nil
}

func (s *AuthService) GetProfile(accessTokenValue string) (*User, error) {
	token, err := s.tokenRepo.FindByValue(accessTokenValue)
	if err != nil {
		return nil, errors.New("invalid access token")
	}

	if token.Type != TokenTypeAccess {
		return nil, errors.New("invalid token type")
	}

	if token.IsExpired() {
		s.tokenRepo.Delete(accessTokenValue)
		return nil, errors.New("access token expired")
	}

	user, err := s.userRepo.FindByID(token.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	return user, nil
}

func (s *AuthService) Logout(refreshTokenValue string) error {
	refreshToken, err := s.tokenRepo.FindByValue(refreshTokenValue)
	if err != nil {
		return errors.New("invalid refresh token")
	}

	s.tokenRepo.DeleteAllUserTokens(refreshToken.UserID, TokenTypeAccess)
	s.tokenRepo.DeleteAllUserTokens(refreshToken.UserID, TokenTypeRefresh)

	return nil
}

func (s *AuthService) validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return errors.New("password must contain at least one number")
	}
	if !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]`).MatchString(password) {
		return errors.New("password must contain at least one special character")
	}
	return nil
}

func (s *AuthService) validateDateOfBirth(dobStr string) error {
	dob, err := time.Parse("2006-01-02", dobStr)
	if err != nil {
		return errors.New("date of birth must be in YYYY-MM-DD format")
	}

	now := time.Now()
	age := now.Year() - dob.Year()

	if now.YearDay() < dob.YearDay() {
		age--
	}

	if age < 13 {
		return errors.New("user must be at least 13 years old")
	}

	if age > 120 {
		return errors.New("invalid date of birth")
	}

	if dob.After(now) {
		return errors.New("date of birth cannot be in the future")
	}

	return nil
}