package handler

import (
	"errors"
	"net/http"

	"gin-demo/internal/user/service"

	"github.com/gin-gonic/gin"
)

// AdminHandler 只负责管理台的 HTTP 层。
// 它和 AuthHandler 共用同一套 token（同样的 AuthMiddleware、同样的库内撤销），
// 区别只在登录入口：管理台不需要 client，也不需要重定向。
type AdminHandler struct {
	authService *service.AuthService
}

func NewAdminHandler(authService *service.AuthService) *AdminHandler {
	return &AdminHandler{authService: authService}
}

// POST /admin/login
//
// 与 /auth/login 的区别：
//   - 不经过 /auth/authorize，所以不需要 client_id / redirect_uri / PKCE
//   - 不建 auth code，成功直接返回 token，也不做 302 跳转
//
// 请求体：{"login_id": "邮箱或用户名", "password": "..."}
func (h *AdminHandler) Login(c *gin.Context) {
	var req struct {
		LoginID  string `json:"login_id" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	accessToken, refreshToken, sessionID, err := h.authService.AdminLogin(c.Request.Context(), req.LoginID, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrNotAdmin):
			// 凭证是对的，只是没有管理员权限。403 而不是 401：
			// 401 会被客户端理解成"该重新登录了"，而这里重新登录也没用。
			c.JSON(http.StatusForbidden, gin.H{"error": "account does not have admin permission"})
		case errors.Is(err, service.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid login_id or password"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	accessTokenString, err := h.authService.SignAccessToken(accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	refreshTokenString, err := h.authService.SignRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessTokenString,
		"refresh_token": refreshTokenString,
		"session_id":    sessionID,
		// expires_in 只描述 access_token，和 /auth/token 保持一致
		"expires_in": int(service.AccessTokenValidPeriod.Seconds()),
	})
}
