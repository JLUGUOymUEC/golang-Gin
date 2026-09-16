package routes

import (
	"gin-demo/internal/gateway/middleware"
	"gin-demo/internal/handler"
	"gin-demo/internal/user/service"

	"github.com/gin-gonic/gin"
)

func RegisterAuthRoutes(
    router *gin.Engine,
    authHandler *handler.AuthHandler,
    authService *service.AuthService,
    clientService *service.ClientService,
) {
    auth := router.Group("/auth")

    // ---- 客户端认证路由：需要 client_id + client_secret ---- 用auth就继承/auth
    clientAuth := auth.Group("")
    clientAuth.Use(middleware.ClientMiddleware(clientService))
    {
        clientAuth.POST("/token", authHandler.ExchangeToken)
        clientAuth.POST("/refresh", authHandler.RefreshToken)
    }

    // ---- 公开路由：不需要 JWT ----
    {
        auth.POST("/register", authHandler.Register)
        auth.GET("/authorize", authHandler.Authorize)
        auth.POST("/login", authHandler.Login)
    }

    // ---- 受保护路由：需要 JWT ----
    protected := auth.Group("")
    protected.Use(middleware.AuthMiddleware(authService))
    {
        protected.POST("/logout", authHandler.Logout)
        protected.POST("/revoke", authHandler.RevokeToken)
        protected.POST("/getprofile", authHandler.GetProfile)
        protected.POST("/updateprofile", authHandler.UpdateProfile)
        protected.POST("/changepassword", authHandler.ChangePassword)
    }

    // ---- 业务 API ----
    api := router.Group("/api/v1")
    api.Use(middleware.AuthMiddleware(authService))
    {
        api.GET("/user/me", func(c *gin.Context) {
            userID, _ := c.Get("user_id")
            c.JSON(200, gin.H{"user_id": userID})
        })
    }
}