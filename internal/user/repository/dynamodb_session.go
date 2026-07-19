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

type DynamoSessionRepository struct {
	client    *dynamodb.Client
	tableName string
}

func NewDynamoSessionRepository(ctx context.Context) (*DynamoSessionRepository, error) {
	client, err := NewDynamoDBConfig(ctx)
	if err != nil {
		err := fmt.Errorf("Failed to load AWS config: %w ", err)
		return nil, err
	}
	tableName := "Sessions"

	return &DynamoSessionRepository{
		client:    client,
		tableName: tableName,
	}, nil
}
func (repo *DynamoSessionRepository) CreateSession(ctx context.Context, session *Session) error {
	if err := session.Validate(); err != nil {
		return fmt.Errorf("Invalid session data: %w", err)
	}
	item, err := attributevalue.MarshalMap(session)
	if err != nil {
		return fmt.Errorf("Failed to marshal session:  %w", err)
	}
	//将项写入DynamoDB表
	_, err = repo.client.PutItem(ctx,
		&dynamodb.PutItemInput{
			TableName:           aws.String(repo.tableName),
			Item:                item,
			ConditionExpression: aws.String("attribute_not_exists(session_id)"),
		})
	if err != nil {
		return fmt.Errorf("Failed to put item: %w ", err)
	}
	return nil
}

func (repo *DynamoSessionRepository) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	resp, err := repo.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"session_id": &types.AttributeValueMemberS{Value: sessionID},
		},
	},
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to get item: %w", err)
	}
	if resp.Item == nil {
		return nil, fmt.Errorf("Session not found")
	}
	var session Session
	err = attributevalue.UnmarshalMap(resp.Item, &session)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal session: %w", err)
	}
	return &session, nil
}

func (repo *DynamoSessionRepository) RefreshSession(ctx context.Context, sessionID string) error {
	nowAt := time.Now().Unix()
	expiredAt := nowAt + 30*24*3600
	_, err := repo.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"session_id": &types.AttributeValueMemberS{Value: sessionID},
		},
		UpdateExpression: aws.String("SET expired_at = :expired_at, revoked = :revoked, ttl = :ttl"), // :占位符
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":expired_at": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", expiredAt)},
			":revoked":    &types.AttributeValueMemberBOOL{Value: false},
			":ttl":        &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", expiredAt)}, //更新TTL字段
		},
		ConditionExpression: aws.String("attribute_exists(session_id)"), //确保存在
	},
	)
	if err != nil {
		return fmt.Errorf("Failed to refresh session: %w", err)
	}

	return nil
}

func (repo *DynamoSessionRepository) DeleteSession(ctx context.Context, sessionID string) error {
	_, err := repo.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &repo.tableName,
		Key: map[string]types.AttributeValue{
			"session_id": &types.AttributeValueMemberS{Value: sessionID},
		},
		ConditionExpression: aws.String("attribute_exists(session_id)"),
	},
	)
	if err != nil {
		return fmt.Errorf("Failed to delete session: %w", err)
	}
	return nil
}

func (repo *DynamoSessionRepository) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := repo.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &repo.tableName,
		Key: map[string]types.AttributeValue{
			"session_id": &types.AttributeValueMemberS{Value: sessionID},
		},
		UpdateExpression: aws.String("SET revoked = :revoked"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":revoked": &types.AttributeValueMemberBOOL{Value: true},
		},
		ConditionExpression: aws.String("attribute_exists(session_id)"),
	},
	)
	if err != nil {
		return fmt.Errorf("Failed to revoke session: %w", err)
	}
	return nil
}

func (repo *DynamoSessionRepository) GetSessionIDsByUserID(ctx context.Context, userID string) ([]string, error) {
	resp, err := repo.client.Query(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(repo.tableName),
		IndexName:                 aws.String("user_id-index"), //  指定用哪个索引
		KeyConditionExpression:    aws.String("user_id = :user_id"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":user_id": &types.AttributeValueMemberS{Value: userID}},
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to query session IDs by user ID: %w", err)
	}
	if resp.Count == 0 {
		return []string{}, nil
	}
	sessionIDs := make([]string, len(resp.Items))
	for i, item := range resp.Items {
		sessionIDAttr, ok := item["session_id"]
		if !ok {
			continue // 或返回错误
		}
		sessionID, ok := sessionIDAttr.(*types.AttributeValueMemberS)
		if !ok {
			continue // 或返回错误
		}
		sessionIDs[i] = sessionID.Value
	}
	return sessionIDs, nil
}
