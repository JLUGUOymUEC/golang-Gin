package repository

import "context"

// ClientRepository defines persistence operations for OAuth clients.
type ClientRepository interface {
	CreateClient(ctx context.Context, client *OAuthClient) error
	GetClientByID(ctx context.Context, clientID string) (*OAuthClient, error)
	DeactivateClient(ctx context.Context, clientID string) error
	ListClients(ctx context.Context, limit int32, cursor string) ([]*OAuthClient, string, error)
}

var _ ClientRepository = (*DynamoClientRepository)(nil)
