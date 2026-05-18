package repository

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

type DynamoUserRepository struct {
	client *dynamodb.Client
	tableName string
}

func NewDynamoUserRepository(client *dynamodb.Client, tableName string) *DynamoUserRepository {
	return &DynamoUserRepository{
		client: client,
		tableName: tableName,
	}
}