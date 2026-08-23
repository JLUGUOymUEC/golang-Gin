package routes

import (
	"gin-demo/internal/gateway/middleware"
	"gin-demo/internal/handler"
	"gin-demo/internal/user/service"

	"github.com/gin-gonic/gin"
)

func RegisterAuthRoutes(router *gin.Engine, authHandler *handler.AuthHandler, authService *service.AuthService) {

	auth := router.Group("/auth")
	auth.Use(middleware.AuthMiddleware(authService))
	{
		auth.POST("/login", authHandler.Login)
		auth.POST("/logout", authHandler.Logout)
		auth.POST("/token", authHandler.ExchangeToken)
		auth.POST("/refresh", authHandler.RefreshToken)
		auth.POST("/revoke", authHandler.RevokeToken)
		auth.POST("/register", authHandler.Register)
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


