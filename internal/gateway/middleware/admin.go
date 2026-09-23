package middleware

import (
	"gin-demo/internal/user/service"

	"github.com/gin-gonic/gin"
)

// AdminMiddleware 判定当前已认证用户是否具备管理员权限。
//
// 两个来源，命中任意一个即可：
//  1. Users 表里的 is_admin 标记 —— 日常手段，跟着数据走
//  2. 配置文件里的 AdminUserIDs 白名单 —— bootstrap / 应急
//     （比如把自己误改成非管理员之后，用它把权限加回来）
//
// 必须挂在 AuthMiddleware 之后：这里依赖的 user_id 来自已验签且已过库校验的 JWT，
// 不能从请求体或 header 直接取。
func AdminMiddleware(userService *service.UserService, adminUserIDs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := GetCurrentUserID(c)
		if !ok {
			// 正常情况到不了这里（前面有 AuthMiddleware）。401 = 没认证。
			c.AbortWithStatusJSON(401, gin.H{"error": "Can't get current user_id"})
			return
		}

		for _, adminUserID := range adminUserIDs {
			if userID == adminUserID {
				c.Next()
				return
			}
		}

		// 查库确认 is_admin。注意 User 的查询带了 ProjectionExpression，
		// 如果那边漏了 is_admin 字段，这里会永远读到 false。
		user, err := userService.GetUserByID(c.Request.Context(), userID)
		if err != nil || user == nil || !user.IsAdmin {
			// 403 而不是 401：身份是合法的，只是权限不够。
			c.AbortWithStatusJSON(403, gin.H{"error": "admin permission required"})
			return
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

// func GetSessionID(c *gin.Context) (string, bool) {
// 	value, ok := c.Get("session_id")
// 	if !ok {
// 			return "", false
// 	}
// 	sessionID, ok := value.(string)
// 	return sessionID, true
// }
