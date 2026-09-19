package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
)

// ErrRefreshTokenNotFound 表示目标 refresh token 不存在（可能已被 TTL 清理）。
var ErrRefreshTokenNotFound = errors.New("refresh token not found")

// ErrRefreshTokenAlreadyRevoked 表示 refresh token 已经被使用或撤销过。
// 这是并发刷新时的"竞争失败"信号：只有第一个请求能成功占用它。
var ErrRefreshTokenAlreadyRevoked = errors.New("refresh token already revoked")

// isConditionalCheckFailed 判断 DynamoDB 返回的是不是条件检查失败。
func isConditionalCheckFailed(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "ConditionalCheckFailedException"
}

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

func (repo *DynamoRefreshTokenRepository) CreateToken(ctx context.Context, token *RefreshToken) error {
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
			ConditionExpression: aws.String("attribute_not_exists(refresh_token_id)"),
		})
	if err != nil {
		return fmt.Errorf("Failed to put item: %w ", err)
	}
	return nil
}

func (repo *DynamoRefreshTokenRepository) GetTokenByID(ctx context.Context, tokenID string) (*RefreshToken, error) {
	resp, err := repo.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"refresh_token_id": &types.AttributeValueMemberS{Value: tokenID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to get item: %w ", err)
	}
	if resp.Item == nil {
		return nil, fmt.Errorf("Refresh Token not found")
	}
	var RefreshToken RefreshToken
	err = attributevalue.UnmarshalMap(resp.Item, &RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal token: %w ", err)
	}
	return &RefreshToken, nil
}

// RevokeToken 原子地把 refresh token 标记为已用。
//
// 条件是"存在且 revoked = false"，因此并发调用时只有一个能成功：
// 其余会返回 ErrRefreshTokenAlreadyRevoked。这是刷新流程防重放的关键，
// 不能退化成只判断 attribute_exists（那样并发请求会全部成功）。
func (repo *DynamoRefreshTokenRepository) RevokeToken(ctx context.Context, tokenID string) error {
	_, err := repo.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"refresh_token_id": &types.AttributeValueMemberS{Value: tokenID},
		},
		UpdateExpression: aws.String("SET revoked = :revoked"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":revoked": &types.AttributeValueMemberBOOL{Value: true},
			":false":   &types.AttributeValueMemberBOOL{Value: false},
		},
		ConditionExpression: aws.String("attribute_exists(refresh_token_id) AND revoked = :false"),
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			// 区分"不存在"和"已被撤销"，便于上层决定是 401 还是其他处理
			if _, getErr := repo.GetTokenByID(ctx, tokenID); getErr != nil {
				return ErrRefreshTokenNotFound
			}
			return ErrRefreshTokenAlreadyRevoked
		}
		return fmt.Errorf("Failed to revoke token: %w ", err)
	}
	return nil
}

// revokeByIDUnconditionally 不做条件判断地置 revoked=true。
// 用于批量撤销：token 可能已被撤销、也可能已被 TTL 删除，这两种情况都不该算失败。
func (repo *DynamoRefreshTokenRepository) revokeByIDUnconditionally(ctx context.Context, tokenID string) error {
	_, err := repo.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(repo.tableName),
		Key: map[string]types.AttributeValue{
			"refresh_token_id": &types.AttributeValueMemberS{Value: tokenID},
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

// RevokeAllByUserID 按 user_id 查出该用户所有 refresh token 并逐个撤销。
// 需要 RefreshTokens 表上名为 user_id-index 的 GSI；GSI 是最终一致的，
// 刚创建、尚未进入索引的 token 可能被漏掉。
func (repo *DynamoRefreshTokenRepository) RevokeAllByUserID(ctx context.Context, userID string) error {
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
			return fmt.Errorf("Failed to query refresh tokens by user_id: %w ", err)
		}
		for _, item := range resp.Items {
			idAttr, ok := item["refresh_token_id"].(*types.AttributeValueMemberS)
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

func (repo *DynamoRefreshTokenRepository) RotateToken(ctx context.Context, tokenID string) (*RefreshToken, error) {
	err := repo.RevokeToken(ctx, tokenID)

	newToken := &RefreshToken{}
	newToken.BeforeCreate()
	if err != nil {
		return nil, fmt.Errorf("Failed to update item: %w ", err)
	}
	return newToken, nil
}

func (repo *DynamoRefreshTokenRepository) GetTokensByUserID(ctx context.Context, userID string) (*RefreshToken, error) {
	resp, err := repo.client.Query(
		ctx,
		&dynamodb.QueryInput{
			TableName:              aws.String(repo.tableName),
			IndexName:              aws.String("user_id-index"), // 与 AccessTokens/Sessions 保持一致
			KeyConditionExpression: aws.String("user_id = :user_id"),
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
	var refreshToken RefreshToken
	err = attributevalue.UnmarshalMap(resp.Items[0], &refreshToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal tokens: %w ", err)
	}
	return &refreshToken, nil
}
