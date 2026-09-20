package middleware

import (
	"github.com/gin-gonic/gin"
)


func AdminMiddleware(adminUserIDs []string) gin.HandlerFunc{
	return func(c *gin.Context){
		adminFlag := false
		user_id , ok := GetCurrentUserID(c)
		if !ok {
			c.AbortWithStatusJSON(401, gin.H{"error": "Can't get current user_id"})
			return 
		}
		for _, adminUserID := range adminUserIDs{
			if user_id == adminUserID{
				adminFlag = true
			}
		}
		if adminFlag == false {
			c.AbortWithStatusJSON(401, gin.H{"error": "don't have permission"})
		}
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

func GetClientID(c *gin.Context) (string, bool) {
	value, ok := c.Get("client_id") // 从上下文获取id
	if !ok {
		return "", false
	}
	clientID, ok := value.(string) // 类型断言
	return clientID, true
}

func GetSessionID(c *gin.Context) (string, bool) {
	value, ok := c.Get("session_id")
	if !ok {
			return "", false
	}
	sessionID, ok := value.(string)
	return sessionID, true
}