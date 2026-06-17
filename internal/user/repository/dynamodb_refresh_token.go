package repository

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DynamoRefreshTokenRepository struct {
	client    *dynamodb.Client
	tableName string
}

func NewDynamoRefreshTokenRepository(ctx context.Context) (*DynamoRefreshTokenRepository, error) {
	client, err := NewDynamoDBConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to load AWS config: %w ", err)
	}
	tableName := "RefreshTokens"
	return &DynamoRefreshTokenRepository{
		client:    client,
		tableName: tableName,
	}, nil
}

func (repo *DynamoRefreshTokenRepository) CreateToken(ctx context.Context, token *RefreshorizeToken) error {
	if err := token.Validate(); err != nil {
		return fmt.Errorf("Invalid token data: %w", err)
	}
	token.BeforeCreate()
	item, err := attributevalue.MarshalMap(token)
	if err != nil {
		return fmt.Errorf("Failed to marshal Refresh_token:  %w", err)
	}
	_, err = repo.client.PutItem(
		ctx,
		&dynamodb.PutItemInput{
			TableName:           aws.String(repo.tableName),
			Item:                item,
			ConditionExpression: aws.String("attribute_not_exists(Refresh_token_id)"),
		})
	if err != nil {
		return fmt.Errorf("Failed to put item: %w ", err)
	}
	return nil
}

func (repo *DynamoRefreshTokenRepository) GetTokenByID(ctx context.Context, tokenID string) (*RefreshorizeToken, error) {
	resp, err := repo.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"Refresh_token_id": &types.AttributeValueMemberS{Value: tokenID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to get item: %w ", err)
	}
	if resp.Item == nil {
		return nil, fmt.Errorf("Refresh Token not found")
	}
	var RefreshToken RefreshorizeToken
	err = attributevalue.UnmarshalMap(resp.Item, &RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal token: %w ", err)
	}
	return &RefreshToken, nil
}

func (repo *DynamoRefreshTokenRepository) GetTokensByUserID(ctx context.Context, userID string) (*RefreshorizeToken, error) {
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
	var RefreshToken RefreshorizeToken
	err = attributevalue.UnmarshalMap(resp.Item, &RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal tokens: %w ", err)
	}
	return &RefreshToken, nil
}

func (repo *DynamoRefreshTokenRepository) RevokeToken(ctx context.Context, tokenID string) error {
	_, err := repo.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"Refresh_token_id": &types.AttributeValueMemberS{Value: tokenID},
		},
		UpdateExpression: aws.String("SET revoked = :revoked"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":revoked": &types.AttributeValueMemberBOOL{Value: true},
		},
		ConditionExpression: aws.String("attribute_exists(Refresh_token_id)"),
	})
	if err != nil {
		return fmt.Errorf("Failed to revoke token: %w ", err)
	}
	return nil
}
