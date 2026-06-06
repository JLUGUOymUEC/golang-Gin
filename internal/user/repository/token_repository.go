package repository

import (
	"context"
)

//方法接口
type AuthTokenRepository interface {
	CreateToken(ctx context.Context, token *AuthorizeToken) error
	GetTokenByID(ctx context.Context, tokenID string) (*AuthorizeToken, error)
	GetTokensByUserID(ctx context.Context, userID string) ([]*AuthorizeToken, error)
	RevokeToken(ctx context.Context, tokenID string) error
}

type AccessTokenRepository interface {
	CreateToken(ctx context.Context, token *AccessToken) error
	GetTokenByID(ctx context.Context, tokenID string) (*AccessToken, error)
	GetTokensByUserID(ctx context.Context, userID string) ([]*AccessToken, error)
	RotateToken(ctx context.Context, tokenID string) error
	RevokeToken(ctx context.Context, tokenID string) error
}

var _ AuthTokenRepository = (*DynamoAuthTokenRepository)(nil)
var _ AccessTokenRepository = (*DynamoAccessTokenRepository)(nil)