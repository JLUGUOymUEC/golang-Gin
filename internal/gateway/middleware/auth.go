package middleware

import (
	"gin-demo/internal/user/service"
	"strings"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware(AuthService *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 格式Authorization: Bearer <token>（JWT字段）信息都在这里
		authHeader  := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "Authorization header is required"})
			return
		}
		// parts := strings.Split(authHeader, " ")
		// 最多切成两段
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(401, gin.H{"error": "Authorization header format must be Bearer {token}"})
			return
		}
		tokenString := parts[1]
		tokenClaims, err := AuthService.ValidateAccessToken(c.Request.Context(),tokenString)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid or expired token"})
		}
		
		c.Set("user_id", tokenClaims.UserID)
		c.Set("token_id", tokenClaims.TokenID)
		c.Next()
	}
}

// func GetCurrentUserID(c *gin.Context) (string, bool) {
// 	value, ok := c.Get("user_id") // 从上下文获取id
// 	if !ok {
// 		return "", false
// 	}
// 	userID, ok := value.(string) // 类型断言
// 	return userID, true
// }
