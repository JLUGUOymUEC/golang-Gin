package service

import (
	"context"
	"fmt"
	"gin-demo/internal/user/repository"
	"time"
)

type SessionService struct {
	repo repository.SessionRepository
}

func (service *SessionService) CreateSession(ctx context.Context, userID string) error {
	session := &repository.Session{
		SessionID: repository.GenerateSessionID(),
		UserID:    userID,
		CreatedAt: time.Now().Unix(),
		ExpiredAt: time.Now().Add(24 * time.Hour).Unix(), //默认过期时间24小时,回来改成configurable,可以不停机更新
		Revoked:   false,
	}
	err := session.Validate()
	if err != nil {
		return fmt.Errorf("Invalid session data: %w ", err)
	}
	err = service.repo.CreateSession(ctx, session)
	if err != nil {
		return fmt.Errorf("Failed to create session: %w ", err)
	}
	return nil
}

func (service *SessionService) ValidateSession(ctx context.Context, sessionID string) (*repository.Session, error) {
	session, err := service.repo.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get session: %w ", err)
	}
	if session == nil {
		return nil, fmt.Errorf("Session with ID %s not found", sessionID)
	}
	if session.Revoked {
		return nil, fmt.Errorf("Session with ID %s is revoked", sessionID)
	}
	if session.ExpiredAt < time.Now().Unix() {
		return nil, fmt.Errorf("Session with ID %s is expired", sessionID)
	}
	return session, nil
}

func (service *SessionService) RefreshSession(ctx context.Context, sessionID string) error {
	err := service.repo.RefreshSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("Failed to refresh session: %w ", err)
	}
	return nil
}

func (service *SessionService) RevokeSession(ctx context.Context, sessionID string) error {

}

func (service *SessionService) DeleteExpiredSessions(ctx context.Context) error {

}

//加一个ttl自动删除超时数据
