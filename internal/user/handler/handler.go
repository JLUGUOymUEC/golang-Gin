package handler

import (
	"context"
	"fmt"
	pb "gin-demo/api/pb/user"
)

type UserServiceServer struct {
	pb.UnimplementedUserServiceServer
}

func (server *UserServiceServer) Handle(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	switch req.Payload.(type) {
	case *pb.UserRequest_RegisterRequest:
		return server.handleRegister(ctx, req.GetRegisterRequest())
	case *pb.UserRequest_LoginRequest:
		return server.handleLogin(ctx, req.GetLoginRequest())
	case *pb.UserRequest_GetUserRequest:
		return server.handleGetUser(ctx, req.GetGetUserRequest())
	case *pb.UserRequest_ListUsersRequest:
		return server.handleListUsers(ctx, req.GetListUsersRequest())
	case *pb.UserRequest_UpdateUserRequest:
		return server.handleUpdateUser(ctx, req.GetUpdateUserRequest())
	default:
		return &pb.UserResponse{
			Code:    1001,
			Message: "Invalid request type",
		}, fmt.Errorf("Invalid request type")
	}

}

func (server *UserServiceServer) handleRegister(ctx context.Context, req *pb.RegisterRequest) (*pb.UserResponse, error) {
	return nil, nil
}
func (server *UserServiceServer) handleLogin(ctx context.Context, req *pb.LoginRequest) (*pb.UserResponse, error) {
	return nil, nil
}

func (server *UserServiceServer) handleGetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	return nil, nil
}

func (server *UserServiceServer) handleListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.UserResponse, error) {
	return nil, nil
}
func (server *UserServiceServer) handleUpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UserResponse, error) {
	return nil, nil
}
