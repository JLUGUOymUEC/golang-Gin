package repository

import (
	"fmt"
)

type Session struct {
	SessionID string `dynamodbav:"session_id"`

	UserID string `dynamodbav:"user_id"`

	CreatedAt int64 `dynamodbav:"created_at"`

	ExpiredAt int64 `dynamodbav:"expired_at"`

	Revoked bool `dynamodbav:"revoked"`
}

func (s *Session) Validate() error {
	if s.UserID == "" {
		return fmt.Errorf("UserID is required")
	}
	return nil
}


_,_ =