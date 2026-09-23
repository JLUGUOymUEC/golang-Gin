package routes

import (
	"gin-demo/internal/handler"

	"github.com/gin-gonic/gin"
)

// RegisterClientRoutes 只保留客户端的公开元数据查询。
//
// 客户端的增删改是管理操作，已经移到 /admin/clients（见 admin_routes.go），
// 不再挂在 /api/v1/clients 上 —— 那里原本同时要求 AuthMiddleware 和
// AdminMiddleware，而拿到 access token 又必须先有 client，形成死锁。
func RegisterClientRoutes(router *gin.Engine, clientHandler *handler.ClientHandler) {
	// 按 client_id 读取客户端的公开配置（redirect_uri / allowed_scopes 等）。
	// 不含 client_secret_hash，所以可以公开。
	router.GET("/api/v1/clients/:clientID", clientHandler.GetClient)
}
