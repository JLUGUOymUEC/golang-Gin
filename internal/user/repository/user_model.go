package repository

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// dyanamodbav标签用于aws-sdk-go-v2的dynamodbav包进行结构体与DynamoDB项之间的映射
type User struct {
	UserID         string `dynamodbav:"user_id"`
	Username       string `dynamodbav:"username"`
	HashedPassword string `dynamodbav:"hashed_password"`
	Email          string `dynamodbav:"email"`
	// IsAdmin 决定该用户能否访问 /admin/* 路由。
	// 它不走任何"创建"路径设置 —— 只能事后直接改库（控制台 UpdateItem 或 CLI），
	// 见 BeforeCreate 里的说明。
	IsAdmin   bool  `dynamodbav:"is_admin"`
	CreatedAt int64 `dynamodbav:"created_at"`
	UpdatedAt int64 `dynamodbav:"updated_at"`
}

func (user *User) Validate() error {
	if user.Username == "" {
		return fmt.Errorf("Username is required")
	}
	if user.HashedPassword == "" {
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
	user.UserID = uuid.New().String()
	// 任何走"创建"路径的用户都强制不是管理员。
	// 注册接口的请求体里本来就没有 is_admin 字段，这里是第二道防线：
	// 即使将来有人不小心给 CreateUser 传了 IsAdmin=true，也会在这里被清掉。
	// 想在库里造出管理员，只能建好之后再手动把这一行改成 true。
	user.IsAdmin = false
}
