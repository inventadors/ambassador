package entities

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