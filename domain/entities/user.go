package entities

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

type Gender string
type RegistrationMethod string

const (
	GenderMale           Gender = "male"
	GenderFemale         Gender = "female"
	GenderOther          Gender = "other"
	GenderPreferNotToSay Gender = "prefer_not_to_say"

	RegMethodEmail  RegistrationMethod = "email"
	RegMethodGoogle RegistrationMethod = "google"
	RegMethodApple  RegistrationMethod = "apple"
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