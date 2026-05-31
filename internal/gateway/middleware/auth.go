package middleware

import (
	"gin-demo/internal/user/service"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware(sessionnService *service.SessionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, err := c.Cookie("session_id")
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
			return
		}
		session, err := sessionnService.ValidateSession(c.Request.Context(), sessionID)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid session"})
			return
		}
		c.Set("user_id", session.UserID)
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
