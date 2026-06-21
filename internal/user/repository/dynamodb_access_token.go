package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DynamoAccessTokenRepository struct {
	client    *dynamodb.Client
	tableName string
}

func NewDynamoAccessTokenRepository(ctx context.Context) (*DynamoAccessTokenRepository, error) {
	client, err := NewDynamoDBConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to load AWS config: %w ", err)
	}
	tableName := "AccessTokens"
	return &DynamoAccessTokenRepository{
		client:    client,
		tableName: tableName,
	}, nil
}

func (repo *DynamoAccessTokenRepository) CreateToken(ctx context.Context, token *AccessToken) error {
	if err := token.Validate(); err != nil {
		return fmt.Errorf("Invalid token data: %w", err)
	}
	token.BeforeCreate()
	item, err := attributevalue.MarshalMap(token)
	if err != nil {
		return fmt.Errorf("Failed to marshal access_token:  %w", err)
	}
	_, err = repo.client.PutItem(
		ctx,
		&dynamodb.PutItemInput{
			TableName:           aws.String(repo.tableName),
			Item:                item,
			ConditionExpression: aws.String("attributes_not_exists(access_token_id)"),
		})
	if err != nil {
		return fmt.Errorf("Failed to put item: %w", err)
	}
	return nil
}

func (repo *DynamoAccessTokenRepository) GetTokenByID(ctx context.Context, tokenID string) (*AccessToken, error) {
	resp, err := repo.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"access_token_id": &types.AttributeValueMemberS{Value: tokenID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to get item: %w ", err)
	}
	if resp.Item == nil {
		return nil, fmt.Errorf("Access Token not found")
	}
	var accessToken AccessToken
	err = attributevalue.UnmarshalMap(resp.Item, accessToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal token: %w ", err)
	}
	return &accessToken, nil
}

func (repo *DynamoAccessTokenRepository) GetTokensByUserID(ctx context.Context, userID string) (*AccessToken, error) {
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
		return nil, fmt.Errorf("Access Tokens not found for user_id: %s", userID)
	}
	var accessToken AccessToken
	err = attributevalue.UnmarshalMap(resp.Item, &accessToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal tokens: %w ", err)
	}
	return &accessToken, nil
}

func (repo *DynamoAccessTokenRepository) RotateToken(ctx context.Context, tokenID string) error {
	nowAt := time.Now().Unix()
	ttl := nowAt + 30*24*3600

	_, err := repo.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"access_token_id": &types.AttributeValueMemberS{Value: tokenID},
		},
		UpdateExpression: aws.String("SET ttl = :ttl"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ttl": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", ttl)},
		},
	})
	if err != nil {
		return fmt.Errorf("Failed to update item: %w ", err)
	}
	return nil
}

func (repo *DynamoAccessTokenRepository) RevokeToken(ctx context.Context, tokenID string) error {
	_, err := repo.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"access_token_id": &types.AttributeValueMemberS{Value: tokenID},
		},
		UpdateExpression: aws.String("Set revoked = :revoked"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":revoked": &types.AttributeValueMemberBOOL{Value: true},
		},
	})
	if err != nil {
		return fmt.Errorf("Failed to revoke token: %w ", err)
	}
	return nil
}
