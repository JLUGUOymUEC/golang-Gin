package repository

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type AuthorizeToken struct {
	AuthTokenID string `dynamodbav:"auth_token_id"`
	UserID      string `dynamodbav:"user_id"`
	CreatedAt   int64  `dynamodbav:"created_at"`
	Revoked     bool   `dynamodbav:"revoked"`
	ttl         int64  `dynamodbav:"ttl"` // DynamoDB TTL字段，自动删除过期数据 5分钟
	RedirectURI string `dynamodbav:"redirect_uri"`
}

type AccessToken struct {
	AccessTokenID string `dynamodbav:"access_token_id"`
	UserID        string `dynamodbav:"user_id"`
	CreatedAt     int64  `dynamodbav:"created_at"`
	Revoked       bool   `dynamodbav:"revoked"`
	ttl           int64  `dynamodbav:"ttl"` // DynamoDB TTL字段，自动删除过期数据 24小时
}

type RefreshToken struct {
	RefreshTokenID string `dynamodbav:"refresh_token_id"`
	UserID         string `dynamodbav:"user_id"`
	CreatedAt      int64  `dynamodbav:"created_at"`
	Revoked        bool   `dynamodbav:"revoked"`
	ttl            int64  `dynamodbav:"ttl"` // DynamoDB TTL字段，自动删除过期数据 7天
}

func (t *AuthorizeToken) Validate() error {
	if t.UserID == "" {
		return fmt.Errorf("UserID is required")
	}
	return nil
}

func (t *AccessToken) Validate() error {
	if t.UserID == "" {
		return fmt.Errorf("UserID is required")
	}
	return nil
}

func (t *RefreshToken) Validate() error {
	if t.UserID == "" {
		return fmt.Errorf("UserID is required")
	}
	return nil
}

func (t *AuthorizeToken) BeforeCreate() {
	now := time.Now().Unix()
	t.CreatedAt = now
	t.ttl = now + 5*60 // 5分钟后过期
	t.AuthTokenID = uuid.New().String()
	t.Revoked = false
}

func (t *AccessToken) BeforeCreate() {
	now := time.Now().Unix()
	t.CreatedAt = now
	t.ttl = now + 24*60*60 // 24小时后过期
	t.AccessTokenID = uuid.New().String()
	t.Revoked = false
}

func (t *RefreshToken) BeforeCreate() {
	now := time.Now().Unix()
	t.CreatedAt = now
	t.ttl = now + 5*60 // 5分钟后过期
	t.RefreshTokenID = uuid.New().String()
	t.Revoked = false
}
