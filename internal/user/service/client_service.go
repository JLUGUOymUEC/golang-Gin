package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"

	"gin-demo/internal/user/repository"
)

type ClientService struct {
	clientRepo repository.ClientRepository
}

type CreateClientInput struct {
	AppName           string
	RedirectURI       string
	AllowedGrantTypes []string
	AllowedScopes     []string
}

func NewClientService(repo repository.ClientRepository) *ClientService {
	return &ClientService{clientRepo: repo}
}

func (service *ClientService) CreateClient(ctx context.Context, input CreateClientInput) (*repository.OAuthClient, string, error) {
	redirectURL, err := url.ParseRequestURI(input.RedirectURI)
	if err != nil || redirectURL.Scheme == "" || redirectURL.Host == "" {
		return nil, "", fmt.Errorf("invalid redirect URI")
	}

	grantTypes := input.AllowedGrantTypes
	if len(grantTypes) == 0 {
		grantTypes = repository.DefaultGrantTypes()
	}
	scopes := input.AllowedScopes
	if len(scopes) == 0 {
		scopes = repository.DefaultGrantScopes()
	}
	
	clientSecret, err := generateClientSecret()
	if err != nil {
		return nil, "", err
	}
	clientSecretHash, err := HashPassword(clientSecret)
	if err != nil {
		return nil, "", fmt.Errorf("hash client secret: %w", err)
	}

	client := &repository.OAuthClient{
		AppName:           input.AppName,
		ClientSecretHash:  clientSecretHash,
		RedirectURI:       input.RedirectURI,
		AllowedGrantTypes: grantTypes,
		AllowedScopes:     scopes,
	}
	client.BeforeCreate()
	if err := client.Validate(); err != nil {
		return nil, "", fmt.Errorf("invalid client data: %w", err)
	}
	if err := service.clientRepo.CreateClient(ctx, client); err != nil {
		return nil, "", fmt.Errorf("create client: %w", err)
	}

	return client, clientSecret, nil
}

func (service *ClientService) GetClientByID(ctx context.Context, clientID string) (*repository.OAuthClient, error) {
	client, err := service.clientRepo.GetClientByID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get client by ID: %w", err)
	}
	return client, nil
}

func (service *ClientService) ListClients(ctx context.Context, limit int32, cursor string) ([]*repository.OAuthClient, string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	clients, nextCursor, err := service.clientRepo.ListClients(ctx, limit, cursor)
	if err != nil {
		return nil, "", fmt.Errorf("list clients: %w", err)
	}
	return clients, nextCursor, nil
}

func (service *ClientService) DeactivateClient(ctx context.Context, clientID string) error {
	if clientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if err := service.clientRepo.DeactivateClient(ctx, clientID); err != nil {
		return fmt.Errorf("deactivate client: %w", err)
	}
	return nil
}

func generateClientSecret() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate client secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}
