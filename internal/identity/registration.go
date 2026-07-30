package identity

import (
	"context"
	"time"
)

type RegisterUser struct {
	Username    string
	DisplayName string
	Email       *string
	Password    string
}

type RegistrationRepository interface {
	CreateWithPassword(context.Context, User, string, time.Time) (User, error)
}

type RegistrationService struct {
	repository RegistrationRepository
	now        func() time.Time
}

func NewRegistrationService(repository RegistrationRepository) *RegistrationService {
	return &RegistrationService{repository: repository, now: time.Now}
}

func (s *RegistrationService) Register(ctx context.Context, input RegisterUser) (User, error) {
	now := s.now().UTC()
	user, err := NewUser(CreateUser{
		Username:    input.Username,
		DisplayName: input.DisplayName,
		Email:       input.Email,
		Status:      UserActive,
	}, now)
	if err != nil {
		return User{}, err
	}
	hash, err := validateAndHashPassword(input.Password)
	if err != nil {
		return User{}, err
	}
	return s.repository.CreateWithPassword(ctx, user, hash, now)
}
