package repositories

import (
	"errors"
	"sync"
	"ambassador/domain/entities"
	"ambassador/domain/repositories"
)

type MemoryUserRepository struct {
	users map[string]*entities.User
	mu    sync.RWMutex
}

func NewMemoryUserRepository() repositories.UserRepository {
	return &MemoryUserRepository{
		users: make(map[string]*entities.User),
	}
}

func (r *MemoryUserRepository) Save(user *entities.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[user.ID] = user
	return nil
}

func (r *MemoryUserRepository) FindByEmail(email string) (*entities.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user.Email.String() == email {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (r *MemoryUserRepository) FindByID(id string) (*entities.User, error) {
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