package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/google/uuid"
)

//dyanamodbav标签用于aws-sdk-go-v2的dynamodbav包进行结构体与DynamoDB项之间的映射
type User struct {
	UserID string `dynamodbav:"user_id"`
	Username string `dynamodbav:"username"`
	Password string `dynamodbav:"password"`
	Email string `dynamodbav:"email"`
	CreatedAt int64 `dynamodbav:"created_at"`
	UpdatedAt int64 `dynamodbav:"updated_at"`
}


func (user *User) Validate() error {
	if user.Username == "" {
		return fmt.Errorf("Username is required")
	}
	if user.Password == "" {
		return fmt.Errorf("Password is required")
	}
	if user.Email == "" {
		return fmt.Errorf("Email is required")
	}
	return nil
}

func (user *User) BeforeCreate() {
	//设置CreatedAt和UpdatedAt等
	now := time.Now().Unix()
	user.CreatedAt = now
	user.UpdatedAt = now
	user.UserID = uuid.New().string()s
}