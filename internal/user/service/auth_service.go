package service

import (
	"context"
	"fmt"
	"gin-demo/internal/user/repository"
)

type AuthService struct {
	userRepo      repository.UserRepository
	sessionServce *SessionService
}

func (service *AuthService) Login(ctx context.Context, loginID string, password string) (*repository.Session, error) {
	user, err := service.userRepo.GetUserByEmail(ctx, loginID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get user by email: %w ", err)
	}
	if user == nil {
		user, err = service.userRepo.GetUserByUsername(ctx, loginID)
		if err != nil {
			return nil, fmt.Errorf("Failed to get user by username: %w ", err)
		}
		if user == nil {
			return nil, fmt.Errorf("user not found")
		}
	}
	if !VerifyPassword(password, user.HashedPassword) {
		return nil, fmt.Errorf("Invalid password for user with email %s", loginID)
	}
	session, err := service.sessionServce.CreateSession(ctx, user.UserID)
	if err != nil {
		return nil, fmt.Errorf("Failed to create session: %w ", err)
	}
	return session, nil
}

func (service *AuthService) Logout(ctx context.Context, sessionID string) error {
	return service.sessionServce.RevokeSession(ctx, sessionID)
}
