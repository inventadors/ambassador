package auth

import "time"

type RegisterRequest struct {
	Email              string             `json:"email" validate:"required,email"`
	FullName           string             `json:"fullName" validate:"required,min=2,max=100"`
	Gender             Gender             `json:"gender" validate:"required,oneof=male female other prefer_not_to_say"`
	DateOfBirth        string             `json:"dateOfBirth" validate:"required"`
	RegistrationMethod RegistrationMethod `json:"registrationMethod" validate:"required,oneof=email google apple"`
	Password           string             `json:"password,omitempty" validate:"required_if=RegistrationMethod email,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

type UserResponse struct {
	ID                 string             `json:"id"`
	Email              string             `json:"email"`
	FullName           string             `json:"fullName"`
	Gender             Gender             `json:"gender"`
	DateOfBirth        string             `json:"dateOfBirth"`
	RegistrationMethod RegistrationMethod `json:"registrationMethod"`
	CreatedAt          time.Time          `json:"createdAt"`
	UpdatedAt          time.Time          `json:"updatedAt"`
}

type AuthResponse struct {
	User         *UserResponse `json:"user"`
	AccessToken  string        `json:"accessToken"`
	RefreshToken string        `json:"refreshToken"`
	ExpiresIn    int64         `json:"expiresIn"`
}

type RefreshResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int64  `json:"expiresIn"`
}

func ToUserResponse(user *User) *UserResponse {
	return &UserResponse{
		ID:                 user.ID,
		Email:              user.Email.String(),
		FullName:           user.FullName,
		Gender:             user.Gender,
		DateOfBirth:        user.DateOfBirth.Format("2006-01-02"),
		RegistrationMethod: user.RegistrationMethod,
		CreatedAt:          user.CreatedAt,
		UpdatedAt:          user.UpdatedAt,
	}
}

func ToAuthResponse(user *User, tokenPair *TokenPair) *AuthResponse {
	expiresIn := int64(tokenPair.AccessToken.ExpiresAt.Sub(time.Now()).Seconds())
	return &AuthResponse{
		User:         ToUserResponse(user),
		AccessToken:  tokenPair.AccessToken.Value,
		RefreshToken: tokenPair.RefreshToken.Value,
		ExpiresIn:    expiresIn,
	}
}

func ToRefreshResponse(tokenPair *TokenPair) *RefreshResponse {
	expiresIn := int64(tokenPair.AccessToken.ExpiresAt.Sub(time.Now()).Seconds())
	return &RefreshResponse{
		AccessToken:  tokenPair.AccessToken.Value,
		RefreshToken: tokenPair.RefreshToken.Value,
		ExpiresIn:    expiresIn,
	}
}
