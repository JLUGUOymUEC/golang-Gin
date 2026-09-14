package routes

import (
	"gin-demo/internal/gateway/middleware"
	"gin-demo/internal/handler"
	"gin-demo/internal/user/service"

	"github.com/gin-gonic/gin"
)

func RegisterAuthRoutes(router *gin.Engine, authHandler *handler.AuthHandler, authService *service.AuthService, clientService *service.ClientService) {
	//这两个方法是客户端认证的路由，使用ClientMiddleware中间件来验证客户端的身份
	clientAuth := router.Group("/auth")
	clientAuth.Use(middleware.ClientMiddleware(clientService))
	{
		clientAuth.POST("/token", authHandler.ExchangeToken)
		clientAuth.POST("/refresh", authHandler.RefreshToken)
	}
	auth := router.Group("/auth")
	publicAuth := router.Group("/auth") // 公开的路由不需要JWT认证
	{

		publicAuth.POST("/register", authHandler.Register)
		publicAuth.GET("/authorize", authHandler.Authorize)
		publicAuth.POST("/login", authHandler.Login)
	}
	auth.Use(middleware.AuthMiddleware(authService))
	{

		auth.POST("/logout", authHandler.Logout)
		auth.POST("/revoke", authHandler.RevokeToken)
		auth.POST("/getprofile", authHandler.GetProfile)
		auth.POST("/updateprofile", authHandler.UpdateProfile)
		auth.POST("/changepassword", authHandler.ChangePassword)
	}
	// 受保护的路由示例
	protected := router.Group("/api/v1")
	protected.Use(middleware.AuthMiddleware(authService))
	{
		protected.GET("/user/me", func(c *gin.Context) {
			userID, _ := c.Get("user_id")
			c.JSON(200, gin.H{"user_id": userID})
		})
	}
}
