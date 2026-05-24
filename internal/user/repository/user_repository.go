package repository

import (
	"context"
)

// 方法接口
type UserRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, userID string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsersWithPagination(ctx context.Context, limit int32, lastToken string) ([]*User, string,error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, userID string) error
}

//编译检查，确保DynamoUserRepository实现了UserRepository接口
var _ UserRepository = (*DynamoUserRepository)(nil)