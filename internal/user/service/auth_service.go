package service

import (
	"context"
	"fmt"
	"gin-demo/internal/user/repository"

	"github.com/golang-jwt/jwt/v5"
)

// type AuthService interface {
//     // 授权码流程
//     CreateAuthCode(ctx context.Context, userID, redirectURI string) (*AuthorizeToken, error)

//     // Token 操作
//     ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error)
//     RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)
//     RevokeToken(ctx context.Context, tokenString string) error
// }

type AuthService struct {
	userRepo      repository.UserRepository
	sessionServce *SessionService
	authTokenRepo repository.AuthTokenRepository
}

type TokenClaims struct {
	UserID   string
	Email    string
	Username string
}

func (service *AuthService) CreateAuthToken(ctx context.Context, userID, redirectURI string) (*repository.AuthorizeToken, error) {
	authToken := &repository.AuthorizeToken{
		UserID:      userID,
		RedirectURI: redirectURI,
		Revoked:     false,
	}
	authToken.BeforeCreate()
	if err := authToken.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid auth code data: %w ", err)
	}
	err := service.authTokenRepo.CreateToken(ctx, authToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to create auth code: %w ", err)
	}
	return authToken, nil //handler里要把token转为字符串返回给客户端
}


func (service *AuthService) ExchangeAuthToken(ctx context.Context, authTokenID string) (*repository.AccessToken, error) {

}

func (service *AuthService) ValidateAccessToken(ctx context.Context, accessToken string) (*TokenClaims, error) {

}

func (service *AuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (*repository.AccessToken, error) {

}

func (service *AuthService) RevokeAccessToken(ctx context.Context, accessToken string) error {
	
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
