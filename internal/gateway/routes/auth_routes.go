package routes

import (
	"gin-demo/internal/gateway/middleware"
	"gin-demo/internal/handler"
	"gin-demo/internal/user/service"

	"github.com/gin-gonic/gin"
)

func RegisterAuthRoutes(router *gin.Engine, authHandler *handler.AuthHandler, authService *service.AuthService) {

	auth := router.Group("/auth")
	publicAuth := router.Group("/auth") // 公开的路由不需要JWT认证
	auth.Use(middleware.AuthMiddleware(authService))
	{
		publicAuth.GET("/authorize", authHandler.Authorize)
		publicAuth.POST("/login", authHandler.Login)
		auth.POST("/logout", authHandler.Logout)
		publicAuth.POST("/token", authHandler.ExchangeToken)
		publicAuth.POST("/refresh", authHandler.RefreshToken)
		auth.POST("/revoke", authHandler.RevokeToken)
		publicAuth.POST("/register", authHandler.Register)
		auth.POST("/getprofile", authHandler.GetProfile)
		auth.POST("/updateprofile", authHandler.UpdateProfile)
		auth.POST("/changepassword", authHandler.ChangePassword)
	}
	protected := router.Group("/api/v1")
	protected.Use(middleware.AuthMiddleware(authService))
	{
		protected.GET("/user/me", func(c *gin.Context) {
			userID, _ := c.Get("user_id")
			c.JSON(200, gin.H{"user_id": userID})
		})
	}
}
