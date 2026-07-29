package handler

import (
	"gin-demo/internal/gateway/middleware"
	"gin-demo/internal/user/repository"
	"gin-demo/internal/user/service"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AuthHandler struct {
	authService    *service.AuthService
	accountService *service.AccountService
	userService    *service.UserService
}

type AuthorizeTokenClaims struct {
	AuthTokenID string `json:"auth_token_id"`
	UserID      string `json:"user_id"`
	CreatedAt   int64  `json:"created_at"`
	Revoked     bool   `json:"revoked"`
	RedirectURI string `json:"redirect_uri"`
	jwt.RegisteredClaims
}

type AccessTokenClaims struct {
	AccessTokenID string `json:"access_token_id"`
	UserID        string `json:"user_id"`
	CreatedAt     int64  `json:"created_at"`
	Revoked       bool   `json:"revoked"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	RefreshTokenID string `json:"refresh_token_id"`
	UserID         string `json:"user_id"`
	CreatedAt      int64  `json:"created_at"`
	Revoked        bool   `json:"revoked"`
	jwt.RegisteredClaims
}

func NewAuthHandler(authService *service.AuthService, accoutService *service.AccountService) *AuthHandler {
	return &AuthHandler{
		authService:    authService,
		accountService: accoutService,
	}
}

func (h *AuthHandler) generateAccessToken(accessToken *repository.AccessToken) (string, error) {
	claims := AccessTokenClaims{
		AccessTokenID: accessToken.AccessTokenID,
		UserID:        accessToken.UserID,
		CreatedAt:     accessToken.CreatedAt,
		Revoked:       accessToken.Revoked,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := tokenClaims.SignedString([]byte(h.authService.GetSecretKey()))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (h *AuthHandler) generateRefreshToken(refreshToken *repository.RefreshToken) (string, error) {
	claims := RefreshTokenClaims{
		RefreshTokenID: refreshToken.RefreshTokenID,
		UserID:         refreshToken.UserID,
		CreatedAt:      refreshToken.CreatedAt,
		Revoked:        refreshToken.Revoked,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := tokenClaims.SignedString([]byte(h.authService.GetSecretKey()))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (h *AuthHandler) generateAuthToken(authToken *repository.AuthorizeToken) (string, error) {
	claims := AuthorizeTokenClaims{
		AuthTokenID: authToken.AuthTokenID,
		UserID:      authToken.UserID,
		CreatedAt:   authToken.CreatedAt,
		Revoked:     authToken.Revoked,
		RedirectURI: authToken.RedirectURI,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := tokenClaims.SignedString([]byte(h.authService.GetSecretKey()))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// POST /auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		LoginID     string `json:"login_id" binding:"required"`
		Password    string `json:"password" binding:"required"`
		RedirectURI string `json:"redirect_uri" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	session, err := h.authService.Login(c.Request.Context(), req.LoginID, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	//后面这个redirectURI
	authToken, err := h.authService.CreateAuthToken(c.Request.Context(), session.UserID, req.RedirectURI)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	authTokenString, err := h.generateAuthToken(authToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"auth_token": authTokenString, "session_id": session.SessionID, "expires_in": 300})
}

// POST /auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// 必须大写，大写才会被解析
	var req struct {
		SessionID string `json:"session_id" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Logout 会通过sessionID注销session和token
	err := h.authService.Logout(c.Request.Context(), req.SessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// POST /auth/token
func (h *AuthHandler) ExchangeToken(c *gin.Context) {
	var req struct {
		AuthToken   string `json:"auth_token" binding:"required"`
		RedirectURI string `json:"redirect_uri" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	accessToken, err := h.authService.ExchangeAuthToken(c.Request.Context(), req.AuthToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	refreshToken, err := h.authService.CreateRefreshToken(c.Request.Context(), accessToken.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	accessTokenString, err := h.generateAccessToken(accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	refreshTokenString, err := h.generateRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"access_token": accessTokenString, "refresh_token": refreshTokenString, "expires_in": 86400})
}

// POST /auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	accessToken, err := h.authService.RefreshAccessToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	// 轮换一个refreshToken
	newRefreshToken, err := h.authService.CreateRefreshToken(c.Request.Context(), accessToken.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	err = h.authService.RevokeRefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	newRefreshTokenString, err := h.generateRefreshToken(newRefreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	accessTokenString, err := h.generateAccessToken(accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"access_token": accessTokenString, "refresh_token": newRefreshTokenString, "expires_in": 86400})
}

// POST /auth/revoke
func (h *AuthHandler) RevokeToken(c *gin.Context) {
	var req struct {
		AccessToken  string `json:"access_token" binding:"required"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err := h.authService.RevokeAccessToken(c.Request.Context(), req.AccessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	if req.RefreshToken != "" {
		err := h.authService.RevokeRefreshToken(c.Request.Context(), req.RefreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
	}
	c.SetCookie("session_id", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Token revoked successfully"})
	return 
}

func (h *AuthHandler) verifyEmailFormat(email string) bool {
	// 正则表达式验证邮箱格式
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// POST /auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if ok := h.verifyEmailFormat(req.Email); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}
	if ok := h.VerifyPasswordFormat(req.Password); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid password format"})
		return
	}
	newUser := &repository.User{
		Username: req.Username,
		Email:    req.Email,
	}
	if err := h.accountService.Register(c.Request.Context(), newUser, req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "user registered successfully"})
	return
}

// POST /auth/get_profile
func (h *AuthHandler) GetProfile(c *gin.Context) {
	user_id, ok := middleware.GetCurrentUserID(c)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Can't get userid from middleware"})
		return
	}
	profile, err := h.accountService.GetProfile(c.Request.Context(), user_id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// GIN会自己序列化
	c.JSON(http.StatusOK, gin.H{"profile": profile})
}

// POST /auth/update_profile
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user_id, ok := middleware.GetCurrentUserID(c)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Can't get userid from middleware"})
		return
	}

	existedUser, err := h.userService.GetUserByID(c.Request.Context(), user_id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if existedUser.Email == req.Email && existedUser.Username == req.Username {
		c.JSON(http.StatusOK, gin.H{"message": "No changes detected"})
		return
	}
	if req.Email != "" && req.Email != existedUser.Email {
		if !h.verifyEmailFormat(req.Email) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
			return
		}
	}
	updatedUser := &repository.User{
		UserID:   user_id,
		Username: req.Username,
		Email:    req.Email,
	}
	if err = h.accountService.UpdateProfile(c.Request.Context(), user_id, updatedUser); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
	return
}

func (h *AuthHandler) VerifyPasswordFormat(password string) bool {
	// 密码规则：8-16位，必须包含大小写字母、数字和特殊字符
	// 长度 8-16 位
	if len(password) < 8 || len(password) > 16 {
		return false
	}

	// 必须包含至少一个小写字母
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	// 必须包含至少一个大写字母
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	// 必须包含至少一个数字
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	// 必须包含至少一个特殊字符（自定义允许的符号）
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]`).MatchString(password)

	return hasLower && hasUpper && hasDigit && hasSpecial
}

// POST /auth/change_password
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	user_id, ok := middleware.GetCurrentUserID(c)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Can't get userid from middleware"})
		return
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !h.VerifyPasswordFormat(req.NewPassword) || req.NewPassword == req.OldPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password Format Error"})
		return
	}
	if err := h.accountService.ChangePassword(c.Request.Context(), user_id, req.OldPassword, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.SetCookie("session_id", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Change Password successfully"})
	return
}
