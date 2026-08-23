package middleware

import (
	"encoding/base64"
	"gin-demo/internal/user/service"
	"strings"

	"github.com/gin-gonic/gin"
)

func ClientMiddleware(ClientService *service.ClientService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 信息在 Authorization: Basic base64(client_id:client_secret) 第二段
		clientHeader := c.GetHeader("Authorization")
		if clientHeader == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "Authorization header is required"})
			return
		}

		parts := strings.SplitN(clientHeader, " ", 2)

		if parts[0] != "Basic" {
			c.AbortWithStatusJSON(401, gin.H{"error": "Authorization header format must be Basic base64(client_id:client_secret)"})
			return
		}
		decodedClient, err := base64.StdEncoding.DecodeString(parts[1])

		partsDecoded := strings.SplitN(string(decodedClient), ":", 2)
		client_id := partsDecoded[0]
		client_secret := partsDecoded[1]
		client, err := ClientService.GetClientByID(c.Request.Context(), client_id)
		hashed_client_secret, err := service.HashPassword(client_secret)
		if err != nil || hashed_client_secret != client.ClientSecretHash {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid or expired secret"})
		}
		c.Set("client_id", client_id)
		c.Set("client_secret", client_secret)
		c.Next()
	}
}

func GetCurrentUserID(c *gin.Context) (string, bool) {
	value, ok := c.Get("user_id") // 从上下文获取id
	if !ok {
		return "", false
	}
	userID, ok := value.(string) // 类型断言
	return userID, true
}
