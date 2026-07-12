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
	userRepo         repository.UserRepository
	sessionServce    *SessionService
	authTokenRepo    repository.AuthTokenRepository
	accessTokenRepo  repository.AccessTokenRepository
	refreshTokenRepo repository.RefreshTokenRepository
	secret           string
}

type TokenClaims struct {
	TokenID              string
	UserID               string
	Email                string
	Username             string
	jwt.RegisteredClaims // 包含标准的JWT声明，如exp、iat等
}

func (service *AuthService) GetSecretKey() string {
	return service.secret
}


func (service *AuthService) CreateRefreshToken(ctx context.Context, userID string) (*repository.RefreshToken,error ) {
	refreshToken := &repository.RefreshToken{ 
		UserID: userID,
	}
	refreshToken.BeforeCreate()
	if err := refreshToken.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid refresh token data: %w ", err)
	}
	return refreshToken, nil
}


func (service *AuthService) RevokeRefreshToken(ctx context.Context, refreshTokenID string) error {
	refreshToken, err := service.refreshTokenRepo.GetTokenByID(ctx, refreshTokenID)	
	if err != nil {
		return fmt.Errorf("Failed to get refresh token: %w ", err)
	}
	if refreshToken.Validate() != nil || refreshToken.Revoked {
		return fmt.Errorf("Refresh token is invalid or revoked")
	}
	err = service.refreshTokenRepo.RevokeToken(ctx, refreshTokenID)
	if err != nil {
		return fmt.Errorf("Failed to revoke refresh token: %w ", err)
	}
	return nil
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
	authToken, err := service.authTokenRepo.GetTokenByID(ctx, authTokenID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get auth token: %w ", err)
	}
	if err = authToken.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid auth token: %w ", err)
	}
	if authToken.Revoked {
		return nil, fmt.Errorf("Auth token is revoked")
	}
	accessToken := &repository.AccessToken{
		UserID:  authToken.UserID,
		Revoked: false,
	}
	accessToken.BeforeCreate()
	if err := accessToken.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid access token data: %w ", err)
	}
	if err := service.accessTokenRepo.CreateToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("Failed to create access token: %w ", err)
	}
	return accessToken, nil
}

func (service *AuthService) ValidateAccessToken(ctx context.Context, accessToken string) (*TokenClaims, error) {
	//eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIiwic2Vzc2lvbl9pZCI6Inh4eCIsImV4cCI6MTY5OTk5OTk5OX0.signature
	// ↑ Header                            ↑ Payload (claims)                  ↑ Signature
	// 使用·jwt库解析和验证Token
	token, err := jwt.ParseWithClaims(accessToken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(service.secret), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("Invalid token: %w ", err)
	}
	if claims, ok := token.Claims.(*TokenClaims); ok {
		return claims, nil
	}
	return nil, fmt.Errorf("Failed to valid token: %w ", err)
}

func (service *AuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (*repository.AccessToken, error) {

	accessToken := &repository.AccessToken{}
	token, err := jwt.ParseWithClaims(refreshToken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(service.secret), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("Invalid refresh token: %w ", err)
	}

	if claims, ok := token.Claims.(*TokenClaims); ok {
		// 验证refresh token是否有效
		refreshTokenRecord, err := service.refreshTokenRepo.GetTokenByID(ctx, claims.TokenID)
		if err != nil {
			return nil, fmt.Errorf("Failed to get refresh token: %w ", err)
		}
		if refreshTokenRecord.Validate() != nil || refreshTokenRecord.Revoked {
			return nil, fmt.Errorf("Refresh token is invalid or revoked")
		}
		// 创建新的access token
		accessToken.UserID = claims.UserID
		accessToken.BeforeCreate()
		if err := accessToken.Validate(); err != nil {
			return nil, fmt.Errorf("Invalid access token data: %w ", err)
		}
		if err := service.accessTokenRepo.CreateToken(ctx, accessToken); err != nil {
			return nil, fmt.Errorf("Failed to create access token: %w ", err)
		}

	}
	return accessToken, nil
}

func (service *AuthService) RevokeAccessToken(ctx context.Context, accessToken string) error {

	token, err := jwt.ParseWithClaims(accessToken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(service.secret), nil
	})
	if err != nil || !token.Valid {
		return fmt.Errorf("Invalid token: %w ", err)
	}
	if claims, ok := token.Claims.(*TokenClaims); ok {
		return service.accessTokenRepo.RevokeToken(ctx, claims.TokenID)
	}
	return fmt.Errorf("Failed to revoke token: %w ", err)
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
