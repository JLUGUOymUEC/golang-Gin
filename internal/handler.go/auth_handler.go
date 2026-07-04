package handler

import (
	"gin-demo/internal/user/repository"
	"gin-demo/internal/user/service"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AuthHandler struct {
	authService *service.AuthService
}

type AuthorizeTokenClaims struct {
	AuthTokenID string `dynamodbav:"auth_token_id"`
	UserID      string `dynamodbav:"user_id"`
	CreatedAt   int64  `dynamodbav:"created_at"`
	Revoked     bool   `dynamodbav:"revoked"`
	RedirectURI string `dynamodbav:"redirect_uri"`
	jwt.RegisteredClaims
}

type AccessTokenClaims struct {
	AccessTokenID string `dynamodbav:"access_token_id"`
	UserID        string `dynamodbav:"user_id"`
	CreatedAt     int64  `dynamodbav:"created_at"`
	Revoked       bool   `dynamodbav:"revoked"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	RefreshTokenID string `dynamodbav:"refresh_token_id"`
	UserID         string `dynamodbav:"user_id"`
	CreatedAt      int64  `dynamodbav:"created_at"`
	Revoked        bool   `dynamodbav:"revoked"`
	jwt.RegisteredClaims
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
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
		Revoked:          refreshToken.Revoked,
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
	accessTokenString ,err := h.generateAccessToken(accessToken)
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
	c.JSON(http.StatusOK, gin.H{"message": "Token revoked successfully"})

}
