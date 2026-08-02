package repository

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DynamoClientRepository struct {
	client    *dynamodb.Client
	tableName string
}

func NewDynamoClientRepository(ctx context.Context) (*DynamoClientRepository, error) {
	client, err := NewDynamoDBConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	return &DynamoClientRepository{
		client:    client,
		tableName: "OAuthClients",
	}, nil
}

func (repo *DynamoClientRepository) CreateClient(ctx context.Context, client *OAuthClient) error {
	if client == nil {
		return fmt.Errorf("OAuth client is required")
	}
	if err := ValidateGrantTypes(client.AllowedGrantTypes); err != nil {
		return err
	}
	if err := ValidateGrantScopes(client.AllowedScopes); err != nil {
		return err
	}

	item, err := attributevalue.MarshalMap(client)
	if err != nil {
		return fmt.Errorf("marshal OAuth client: %w", err)
	}

	_, err = repo.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(repo.tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(client_id)"),
	})
	if err != nil {
		return fmt.Errorf("create OAuth client: %w", err)
	}

	return nil
}

func (repo *DynamoClientRepository) GetClientByID(ctx context.Context, clientID string) (*OAuthClient, error) {
	resp, err := repo.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"client_id": &types.AttributeValueMemberS{Value: clientID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("get OAuth client: %w", err)
	}
	if len(resp.Item) == 0 {
		return nil, fmt.Errorf("OAuth client not found")
	}

	var client OAuthClient
	if err := attributevalue.UnmarshalMap(resp.Item, &client); err != nil {
		return nil, fmt.Errorf("unmarshal OAuth client: %w", err)
	}

	return &client, nil
}

func (repo *DynamoClientRepository) DeactivateClient(ctx context.Context, clientID string) error {
	_, err := repo.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"client_id": &types.AttributeValueMemberS{Value: clientID},
		},
		UpdateExpression: aws.String("SET is_active = :inactive"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":inactive": &types.AttributeValueMemberBOOL{Value: false},
		},
		ConditionExpression: aws.String("attribute_exists(client_id)"),
	})
	if err != nil {
		return fmt.Errorf("deactivate OAuth client: %w", err)
	}

	return nil
}

func (repo *DynamoClientRepository) ListClients(ctx context.Context, limit int32, cursor string) ([]*OAuthClient, string, error) {
	var startKey map[string]types.AttributeValue
	if cursor != "" {
		var err error
		startKey, err = attributevalue.UnmarshalMapJSON([]byte(cursor))
		if err != nil {
			return nil, "", fmt.Errorf("invalid cursor: %w", err)
		}
	}

	resp, err := repo.client.Scan(ctx, &dynamodb.ScanInput{
		TableName:         aws.String(repo.tableName),
		Limit:             aws.Int32(limit),
		ExclusiveStartKey: startKey,
	})
	if err != nil {
		return nil, "", fmt.Errorf("scan OAuth clients: %w", err)
	}

	var clients []*OAuthClient
	if err := attributevalue.UnmarshalListOfMaps(resp.Items, &clients); err != nil {
		return nil, "", fmt.Errorf("unmarshal OAuth clients: %w", err)
	}

	nextCursor := ""
	if len(resp.LastEvaluatedKey) > 0 {
		data, err := attributevalue.MarshalMapJSON(resp.LastEvaluatedKey)
		if err != nil {
			return nil, "", fmt.Errorf("marshal next cursor: %w", err)
		}
		nextCursor = string(data)
	}

	return clients, nextCursor, nil
}
