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

func (service *AuthService) Login(ctx context.Context, loginID string, password string) (*repository.User, error) {
	user, err := service.userRepo.GetUserByEmail(ctx, loginID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get user by email: %w ", err)
	}
	if user == nil {
		user, err = service.userRepo.GetUserByUsername(ctx, loginID)
		if err != nil {
			return nil, fmt.Errorf("Failed to get user by username: %w ", err)
		}
		if user != nil {
			return nil, nil
		}
	}
	//验证密码 还没做密码服务
	if user.Password != password {
		return nil, nil
	}
	service.sessionServce.CreateSession(ctx, loginID)
}

func (service *AuthService) Logout(ctx context.Context, sessionID string) error {
}
