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
	err = attributevalue.UnmarshalMap(resp.Item, &accessToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal token: %w ", err)
	}
	return &accessToken, nil
}

func (repo *DynamoAccessTokenRepository) GetTokensByUserID(ctx context.Context, userID string) (*AccessToken, error) {
	resp, err := repo.client.Query(
		ctx,
		&dynamodb.QueryInput{
			TableName:              aws.String(repo.tableName),
			IndexName:              aws.String("userID-index"), // 需要"userID-index""
			KeyConditionExpression: aws.String("userID = :user_id"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":userID": &types.AttributeValueMemberS{
					Value: userID,
				},
			},
		})
	if err != nil {
		return nil, fmt.Errorf("Failed to get items: %w ", err)
	}
	if resp.Items == nil || len(resp.Items) > 1 {
		return nil, fmt.Errorf("Access Tokens not found for user_id: %s", userID)
	}
	var accessToken AccessToken
	err = attributevalue.UnmarshalMap(resp.Items[0], &accessToken)
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
	return repo.revokeByIDUnconditionally(ctx, tokenID)
}

// revokeByIDUnconditionally 不做条件判断地置 revoked=true。
// 用于批量撤销：token 可能已被撤销、也可能已被 TTL 删除，这两种情况都不该算失败。
func (repo *DynamoAccessTokenRepository) revokeByIDUnconditionally(ctx context.Context, tokenID string) error {
	_, err := repo.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"access_token_id": &types.AttributeValueMemberS{Value: tokenID},
		},
		UpdateExpression: aws.String("SET revoked = :revoked"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":revoked": &types.AttributeValueMemberBOOL{Value: true},
		},
	})
	if err != nil {
		return fmt.Errorf("Failed to revoke token: %w ", err)
	}
	return nil
}

// RevokeAllByUserID 按 user_id 查出该用户所有 access token 并逐个撤销。
// 需要 AccessTokens 表上名为 user_id-index 的 GSI；GSI 是最终一致的，
// 刚创建、尚未进入索引的 token 可能被漏掉。
func (repo *DynamoAccessTokenRepository) RevokeAllByUserID(ctx context.Context, userID string) error {
	var startKey map[string]types.AttributeValue
	for {
		resp, err := repo.client.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(repo.tableName),
			IndexName:              aws.String("user_id-index"),
			KeyConditionExpression: aws.String("user_id = :user_id"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":user_id": &types.AttributeValueMemberS{Value: userID},
			},
			ExclusiveStartKey: startKey,
		})
		if err != nil {
			return fmt.Errorf("Failed to query access tokens by user_id: %w ", err)
		}
		for _, item := range resp.Items {
			idAttr, ok := item["access_token_id"].(*types.AttributeValueMemberS)
			if !ok {
				continue
			}
			if err := repo.revokeByIDUnconditionally(ctx, idAttr.Value); err != nil {
				return err
			}
		}
		if len(resp.LastEvaluatedKey) == 0 {
			return nil
		}
		startKey = resp.LastEvaluatedKey
	}
}
