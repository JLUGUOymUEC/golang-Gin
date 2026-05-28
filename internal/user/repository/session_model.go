package repository

import (
	"fmt"

	"github.com/google/uuid"
)

type Session struct {
	SessionID string `dynamodbav:"session_id"`

	UserID string `dynamodbav:"user_id"`

	CreatedAt int64 `dynamodbav:"created_at"`

	ExpiredAt int64 `dynamodbav:"expired_at"`

	Revoked bool `dynamodbav:"revoked"`

	TTL int64 `dynamodbav:"ttl"` // DynamoDB TTL字段，自动删除过期数据
}

func (s *Session) Validate() error {
	if s.UserID == "" {
		return fmt.Errorf("UserID is required")
	}
	return nil
}

func GenerateSessionID() string {
	return fmt.Sprintf("sess_%s", uuid.New().String())
}
