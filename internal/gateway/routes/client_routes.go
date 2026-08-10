package routes

import (
	"gin-demo/internal/gateway/middleware"
	"gin-demo/internal/handler"
	"gin-demo/internal/user/service"

	"github.com/gin-gonic/gin"
)

func RegisterClientRoutes(router *gin.Engine, clientHandler *handler.ClientHandler, authService *service.AuthService) {
	clients := router.Group("/api/v1/clients")
	clients.Use(middleware.AuthMiddleware(authService))
	{
		clients.POST("", clientHandler.CreateClient)
		clients.GET("", clientHandler.ListClients)
		clients.GET("/:clientID", clientHandler.GetClient)
		clients.DELETE("/:clientID", clientHandler.DeactivateClient)
	}
}
