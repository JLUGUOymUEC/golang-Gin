package service

import (
	"context"
	"fmt"
	"gin-demo/internal/user/repository"
	"time"
)

type AccountService struct {
	userRepo       repository.UserRepository
	SessionService *SessionService
}

type UserProfile struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	CreatedAt int64  `json:"created_at"`
}

func (service *AccountService) Register(ctx context.Context, user *repository.User, password string) error {
	if err := user.Validate(); err != nil {
		return fmt.Errorf("Invalid user data: %w", err)
	}
	user.BeforeCreate()
	existedUser, err := service.userRepo.GetUserByUsername(ctx, user.Username)
	if existedUser != nil {
		return fmt.Errorf("Username already exists")
	} else if err != nil && err.Error() != "User not found" {
		return fmt.Errorf("Failed to check existing username: %w", err)
	}
	existedUser, err = service.userRepo.GetUserByEmail(ctx, user.Email)
	if existedUser != nil {
		return fmt.Errorf("Email already exists")
	} else if err != nil && err.Error() != "User not found" {
		return fmt.Errorf("Failed to check existing username: %w", err)
	}
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("Failed to hash password: %w", err)
	}
	user.HashedPassword = hashedPassword

	err = service.userRepo.CreateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("Failed to create user: %w", err)
	}

	return nil
}

func (service *AccountService) GetProfile(ctx context.Context, userID string) (*UserProfile, error) {
	user, err := service.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get user profile: %w", err)
	}
	profile := &UserProfile{
		UserID:    user.UserID,
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}
	return profile, nil

}

func (service *AccountService) UpdateProfile(ctx context.Context, userID string, updatedUser *repository.User) error {
	user, err := service.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("Failed to get user profile: %w", err)
	}
	existedUser, err := service.userRepo.GetUserByEmail(ctx, updatedUser.Email)
	if existedUser != nil && existedUser.UserID != userID {
		return fmt.Errorf("Email already exists")
	} else if err != nil && err.Error() != "User not found" {
		return fmt.Errorf("Failed to check existing username: %w", err)
	}

	existedUser, err = service.userRepo.GetUserByUsername(ctx, updatedUser.Username)
	if existedUser != nil && existedUser.UserID != userID {
		return fmt.Errorf("Username already exists")
	} else if err != nil && err.Error() != "User not found" {
		return fmt.Errorf("Failed to check existing username: %w", err)
	}

	user.Email = updatedUser.Email
	user.Username = updatedUser.Username
	user.UpdatedAt = time.Now().Unix()
	err = service.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("Failed to update user profile: %w", err)
	}
	return nil
}

func (service *AccountService) ChangePassword(ctx context.Context, userID string, oldPassword string, newPassowrd string) error {
	user, err := service.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("Failed to update user profile: %w", err)
	}
	if !VerifyPassword(oldPassword, user.HashedPassword) {
		return fmt.Errorf("Old password is incorrect")
	}
	hashedPassword, err := HashPassword(newPassowrd)
	if err != nil {
		return fmt.Errorf("Failed to hash new password: %w", err)
	}
	user.HashedPassword = hashedPassword
	user.UpdatedAt = time.Now().Unix()
	err = service.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("Failed to update user password: %w", err)
	}
	sessionIDs, err := service.SessionService.GetSessionIDsByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("Failed to get user sessions: %w", err)
	}
	for _, sessionID := range sessionIDs {
		if err = service.SessionService.RevokeSession(ctx, sessionID); err != nil {
			return fmt.Errorf("Failed to revoke user sessions: %w", err)
		}
	}

	return nil
}
