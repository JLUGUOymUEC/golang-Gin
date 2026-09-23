package routes

import (
	"gin-demo/internal/gateway/middleware"
	"gin-demo/internal/handler"
	"gin-demo/internal/user/service"

	"github.com/gin-gonic/gin"
)

// RegisterAdminRoutes 注册管理台路由。
//
// 管理台是"第一方"应用，和面向第三方客户端的 /auth/authorize + /auth/token
// 分开走两条入口：
//
//	第三方客户端：client 凭据 → /auth/token（需要预先存在的 client）
//	管理台：账号密码    → /admin/login（不需要 client）
//
// 这个分离解开了启动死锁 —— 否则"建 client 需要 token，拿 token 需要 client"。
//
// token 本身是同一套：/admin/* 复用 AuthMiddleware，因此库内撤销、TTL 检查
// 这些机制对管理员同样生效，不需要第二套 token 体系。
func RegisterAdminRoutes(
	router *gin.Engine,
	adminHandler *handler.AdminHandler,
	clientHandler *handler.ClientHandler,
	authService *service.AuthService,
	userService *service.UserService,
	adminUserIDs []string,
) {
	// 公开：管理员登录。这是密码接口，必须靠限流挡住爆破，
	// 目前依赖 router 级别的 RateLimitMiddleware。
	router.POST("/admin/login", adminHandler.Login)

	admin := router.Group("/admin")
	admin.Use(middleware.AuthMiddleware(authService))
	admin.Use(middleware.AdminMiddleware(userService, adminUserIDs))
	{
		admin.POST("/clients", clientHandler.CreateClient)
		admin.GET("/clients", clientHandler.ListClients)
		admin.DELETE("/clients/:clientID", clientHandler.DeactivateClient)
	}
}
