package repository

import (
	"context"
)

type SessionRepository interface {
	CreateSession(
		ctx context.Context,
		session *Session,
	) error

	GetSession(
		ctx context.Context,
		sessionID string,
	) (*Session, error)

	RefreshSession(
		ctx context.Context,
		sessionID string,
	) error

	DeleteSession(
		ctx context.Context,
		sessionID string,
	) error

	RevokeSession(
		ctx context.Context,
		sessionID string,
	) error
}

var _ SessionRepository = (*DynamoSessionRepository)(nil)
