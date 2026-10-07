package routes

import (
	"gin-demo/internal/handler"

	"github.com/gin-gonic/gin"
)

func RegisterOIDCRoutes(router *gin.Engine, oidcHandler *handler.OIDCHandler) {
	router.GET("/.well-known/jwks.json", oidcHandler.JWKS)
	router.GET("/.well-known/openid-configuration", oidcHandler.Discovery)
}
