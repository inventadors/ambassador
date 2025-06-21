package repositories

import "ambassador/domain/entities"

type UserRepository interface {
	Save(user *entities.User) error
	FindByEmail(email string) (*entities.User, error)
	FindByID(id string) (*entities.User, error)
	ExistsByEmail(email string) (bool, error)
}