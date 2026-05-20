package repository

import (
	"context"
	"fmt"
	
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"gin-demo/internal/user/model"
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
		err := fmt.Errorf("Failed to load AWS config: " + err.Error())
		return nil, err
	}
	tableName := "Users"

	return &DynamoUserRepository{
		client:    client,
		tableName: tableName,
	}, nil
}


func (repo *DynamoUserRepository)CreateUser(ctx context.Context, user *model.User) error {
	if err := user.Validate();err != nil{
		return err
	}
	user.BeforeCreate()
	//将User结构体转换为DynamoDB项
	item, err := attributevalue.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("Failed to marshal user: " + err.Error())	
	}
	//将项写入DynamoDB表
	_, err = repo.client.PutItem(ctx , 
		&dynamodb.PutItemInput{
			TableName: &repo.tableName,
			Item: item,
		})
	if err != nil {
		return fmt.Errorf("Failed to put item: " + err.Error())
	}
	return nil
}

func (repo *DynamoUserRepository) GetUserByID(ctx context