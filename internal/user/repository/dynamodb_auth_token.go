package repository

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// CreateToken(ctx context.Context, token *AuthorizeToken) error
// GetTokenByID(ctx context.Context, tokenID string) (*AuthorizeToken, error)
// GetTokensByUserID(ctx context.Context, userID string) ([]*AuthorizeToken, error)
// RevokeToken(ctx context.Context, tokenID string) error

type DynamoAuthTokenRepository struct {
	client    *dynamodb.Client
	tableName string
}

func NewDynamoAuthTokenRepository(ctx context.Context) (*DynamoAuthTokenRepository, error) {
	client, err := NewDynamoDBConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to load AWS config: %w ", err)
	}
	tableName := "AuthTokens"
	return &DynamoAuthTokenRepository{
		client:    client,
		tableName: tableName,
	}, nil
}

func (repo *DynamoAuthTokenRepository) CreateToken(ctx context.Context, token *AuthorizeToken) error {
	if err := token.Validate(); err != nil {
		return fmt.Errorf("Invalid token data: %w", err)
	}
	token.BeforeCreate()
	item, err := attributevalue.MarshalMap(token)
	if err != nil {
		return fmt.Errorf("Failed to marshal auth_token:  %w", err)
	}
	_, err = repo.client.PutItem(
		ctx,
		&dynamodb.PutItemInput{
			TableName:           aws.String(repo.tableName),
			Item:                item,
			ConditionExpression: aws.String("attribute_not_exists(auth_token_id)"),
		})
	if err != nil {
		return fmt.Errorf("Failed to put item: %w ", err)
	}
	return nil
}

func (repo *DynamoAuthTokenRepository) GetTokenByID(ctx context.Context, tokenID string) (*AuthorizeToken, error) {
	resp, err := repo.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"auth_token_id": &types.AttributeValueMemberS{Value: tokenID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to get item: %w ", err)
	}
	if resp.Item == nil {
		return nil, fmt.Errorf("Auth Token not found")
	}
	var authToken AuthorizeToken
	err = attributevalue.UnmarshalMap(resp.Item, &authToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal token: %w ", err)
	}
	return &authToken, nil
}

func (repo *DynamoAuthTokenRepository) GetTokensByUserID(ctx context.Context, userID string) (*AuthorizeToken, error) {
	resp, err := repo.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"user_id": &types.AttributeValueMemberS{Value: userID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to get items: %w ", err)
	}
	if resp.Item == nil {
		return nil, fmt.Errorf("No tokens found for user")
	}
	var authToken AuthorizeToken
	err = attributevalue.UnmarshalMap(resp.Item, &authToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal tokens: %w ", err)
	}
	return &authToken, nil
}

func (repo *DynamoAuthTokenRepository) RevokeToken(ctx context.Context, tokenID string) error {
	_, err := repo.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"auth_token_id": &types.AttributeValueMemberS{Value: tokenID},
		},
		UpdateExpression: aws.String("SET revoked = :revoked"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":revoked": &types.AttributeValueMemberBOOL{Value: true},
		},
		ConditionExpression: aws.String("attribute_exists(auth_token_id)"),
	})
	if err != nil {
		return fmt.Errorf("Failed to revoke token: %w ", err)
	}
	return nil
}
