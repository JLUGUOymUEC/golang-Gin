package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DynamoUserRepository struct {
	client    *dynamodb.Client
	tableName string
}

func NewDynamoDBConfig(ctx context.Context) (*dynamodb.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("ap-northeast-1"))
	if err != nil {
		return nil, err
	}
	dbClient := dynamodb.NewFromConfig(cfg)

	return dbClient, nil
}

func NewDynamoUserRepository(ctx context.Context) (*DynamoUserRepository, error) {
	client, err := NewDynamoDBConfig(ctx)
	if err != nil {
		err := fmt.Errorf("Failed to load AWS config: %w ", err)
		return nil, err
	}
	tableName := "Users"

	return &DynamoUserRepository{
		client:    client,
		tableName: tableName,
	}, nil
}

func (repo *DynamoUserRepository) CreateUser(ctx context.Context, user *User) error {
	if err := user.Validate(); err != nil {
		return err
	}
	user.BeforeCreate()
	//将User结构体转换为DynamoDB项
	item, err := attributevalue.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("Failed to marshal user:  %w", err)
	}
	//将项写入DynamoDB表
	_, err = repo.client.PutItem(ctx,
		&dynamodb.PutItemInput{
			TableName: aws.String(repo.tableName),
			Item:      item,
		})
	if err != nil {
		return fmt.Errorf("Failed to put item: %w ", err)
	}
	return nil
}

func (repo *DynamoUserRepository) GetUserByID(ctx context.Context, userID string) (*User, error) {
	resp, err := repo.client.GetItem(
		ctx,
		&dynamodb.GetItemInput{
			TableName: aws.String(repo.tableName),

			ProjectionExpression: aws.String(
				"user_id, username, hashed_password, email, created_at, updated_at",
			),

			Key: map[string]types.AttributeValue{
				"user_id": &types.AttributeValueMemberS{
					Value: userID,
				},
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to query item: %w ", err)
	}
	//判断没有找到数据
	if len(resp.Item) == 0 {
		fmt.Println("User not found")
		return nil, nil
	}
	var user User
	err = attributevalue.UnmarshalMap(
		resp.Item,
		&user,
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal user:  %w", err)
	}
	return &user, nil
}

func (repo *DynamoUserRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	resp, err := repo.client.Query(
		ctx,
		&dynamodb.QueryInput{
			TableName:              aws.String(repo.tableName),
			KeyConditionExpression: aws.String("username = :userName"),
			ProjectionExpression: aws.String(
				"user_id, username, hashed_password, email, created_at, updated_at",
			),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":userName": &types.AttributeValueMemberS{
					Value: username,
				},
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to query item: %w ", err)
	}
	if len(resp.Items) == 0 {
		fmt.Println("User not found")
		return nil, nil
	}
	var users []User
	err = attributevalue.UnmarshalListOfMaps(resp.Items, &users)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal user: %w ", err)
	}
	return &users[0], nil
}

func (repo *DynamoUserRepository) ListUsersWithPagination(ctx context.Context, limit int32, lastToken string) ([]*User, string, error) {
	input := &dynamodb.ScanInput{
		TableName: aws.String(repo.tableName),
		Limit:     aws.Int32(limit),
	}

	// 如果有 lastToken，解析并设置 ExclusiveStartKey
	if lastToken != "" {
		var exclusiveStartKey map[string]types.AttributeValue
		err := json.Unmarshal([]byte(lastToken), &exclusiveStartKey)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse last token: %w", err)
		}
		input.ExclusiveStartKey = exclusiveStartKey
	}

	resp, err := repo.client.Scan(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("failed to scan users: %w", err)
	}

	// 解析用户列表
	var users []*User
	err = attributevalue.UnmarshalListOfMaps(resp.Items, &users)
	if err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal users: %w", err)
	}

	// 生成下一页的 token
	nextToken := ""
	if resp.LastEvaluatedKey != nil {
		tokenBytes, err := json.Marshal(resp.LastEvaluatedKey)
		if err != nil {
			return nil, "", fmt.Errorf("failed to marshal last key: %w", err)
		}
		nextToken = string(tokenBytes)
	}

	return users, nextToken, nil
}

func (repo *DynamoUserRepository) UpdateUser(ctx context.Context, user *User) error {
	if err := user.Validate(); err != nil {
		return fmt.Errorf("Update userinfo validate failed")
	}

	updates := []string{}
	values := make(map[string]types.AttributeValue)
	//每次更新都要更新updated_at字段
	values["updated_at"] = &types.AttributeValueMemberN{
		Value: fmt.Sprintf("%d", user.UpdatedAt),
	}
	//判断各个字段是否为空
	if user.Username != "" {
		values["username"] = &types.AttributeValueMemberS{
			Value: user.Username,
		}
		updates = append(updates, "username = :username")
	}
	if user.HashedPassword != "" {
		values["hashed_password"] = &types.AttributeValueMemberS{
			Value: user.HashedPassword,
		}
		updates = append(updates, "hashed_password = :hashed_password")
	}
	if user.Email != "" {
		values["email"] = &types.AttributeValueMemberS{
			Value: user.Email,
		}
		updates = append(updates, "email = :email")
	}
	updateExpr := "SET " + strings.Join(
		updates,
		", ",
	)
	_, err := repo.client.UpdateItem(
		ctx,
		&dynamodb.UpdateItemInput{
			TableName:        aws.String(repo.tableName),
			UpdateExpression: aws.String(updateExpr),
			Key: map[string]types.AttributeValue{
				"user_id": &types.AttributeValueMemberS{
					Value: user.UserID,
				},
			},
			ExpressionAttributeValues: values,
			ReturnValues:              types.ReturnValueUpdatedNew,
			ConditionExpression:       aws.String("attribute_exists(user_id)"), //确保用户存在
		},
	)
	return err
}

func (repo *DynamoUserRepository) DeleteUser(ctx context.Context, userID string) error {
	condition := "attribute_exists(user_id)"
	_, err := repo.client.DeleteItem(
		ctx,
		&dynamodb.DeleteItemInput{
			TableName: aws.String(repo.tableName),
			Key: map[string]types.AttributeValue{
				"user_id": &types.AttributeValueMemberS{
					Value: userID,
				},
			},
			ConditionExpression: aws.String(condition),
		},
	)
	if err != nil {
		return fmt.Errorf("Failed to delete item: %w", err)
	}
	return nil
}

func (repo *DynamoUserRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	resp, err := repo.client.GetItem(
		ctx,
		&dynamodb.GetItemInput{
			TableName: aws.String(repo.tableName),
			ProjectionExpression: aws.String(
				"user_id, username, hashed_password, email, created_at, updated_at",
			),
			Key: map[string]types.AttributeValue{
				"email": &types.AttributeValueMemberS{
					Value: email,
				},
			},
		})
	if err != nil {
		return nil, fmt.Errorf("Failed to query item: %w ", err)
	}
	if len(resp.Item) == 0 {
		fmt.Println("User not found")
		return nil, nil
	}
	var user User
	err = attributevalue.UnmarshalMap(
		resp.Item,
		&user,
	)
	return &user, nil
}
