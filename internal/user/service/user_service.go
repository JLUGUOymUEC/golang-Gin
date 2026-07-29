package service

import (
	"context"
	"fmt"
	"gin-demo/internal/user/repository"
)

type UserService struct {
	repo repository.UserRepository
}

func (service *UserService) CreateUser(ctx context.Context, hashedPassword, email, username string) (*repository.User, error) {
	exists, err := service.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("Failed to check existing user: %w ", err)
	}
	if exists != nil {
		return nil, fmt.Errorf("User with email %s already exists", email)
	}

	user := &repository.User{
		Username:       username,
		HashedPassword: hashedPassword,
		Email:          email,
	}
	err = user.Validate()
	if err != nil {
		return nil, fmt.Errorf("Invalid user data: %w ", err)
	}
	err = service.repo.CreateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("Failed to create user: %w ", err)
	}
	return user, nil
}

func (service *UserService) GetUserByID(ctx context.Context, userID string) (*repository.User, error) {
	user, err := service.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get user by ID: %w ", err)
	}
	if user == nil {
		return nil, nil
	}
	return user, nil
}

func (service *UserService) GetUserByEmail(ctx context.Context, email string) (*repository.User, error) {
	user, err := service.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("Failed to get user by email: %w ", err)
	}
	if user == nil {
		return nil, nil
	}
	return user, nil
}

func (service *UserService) GetUserByUsername(ctx context.Context, username string) (*repository.User, error) {
	user, err := service.repo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("Failed to get user by username: %w ", err)
	}
	if user == nil {
		return nil, fmt.Errorf("User with username %s not found", username)
	}
	return user, nil
}

func (service *UserService) ListUsers(ctx context.Context, limit int32, lastToken string) ([]*repository.User, string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20 // 默认每页20条，最大100条
	}
	users, next_token, err := service.repo.ListUsersWithPagination(ctx, limit, lastToken)

	if err != nil {
		return nil, "", fmt.Errorf("Failed to list users: %w ", err)
	}
	return users, next_token, nil
}

func (service *UserService) UpdateUser(ctx context.Context, user *repository.User) error {
	err := service.repo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("Failed to update user: %w ", err)
	}
	return nil
}

func (service *UserService) DeleteUser(ctx context.Context, userID string) error {
	err := service.repo.DeleteUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("Failed to delete user: %w ", err)
	}
	return nil
}
