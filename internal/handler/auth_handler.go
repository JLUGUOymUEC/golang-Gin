package handler

import (
	"encoding/base64"
	"fmt"
	"gin-demo/internal/gateway/middleware"
	"gin-demo/internal/user/repository"
	"gin-demo/internal/user/service"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AuthHandler struct {
	authService    *service.AuthService
	accountService *service.AccountService
	userService    *service.UserService
	clientService  *service.ClientService
}

const authorizationRequestCookie = "oidc_authorization_request"

type authorizationRequestClaims struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	jwt.RegisteredClaims
}

func NewAuthHandler(authService *service.AuthService, accountService *service.AccountService, userService *service.UserService, clientService *service.ClientService) *AuthHandler {
	return &AuthHandler{
		authService:    authService,
		accountService: accountService,
		userService:    userService,
		clientService:  clientService,
	}
}

func (h *AuthHandler) generateAccessToken(accessToken *repository.AccessToken) (string, error) {
	claims := service.AccessTokenClaims{
		AccessTokenID: accessToken.AccessTokenID,
		UserID:        accessToken.UserID,
		CreatedAt:     accessToken.CreatedAt,
		Revoked:       accessToken.Revoked,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), //1小时以后过期
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
	claims := service.RefreshTokenClaims{
		RefreshTokenID: refreshToken.RefreshTokenID,
		UserID:         refreshToken.UserID,
		CreatedAt:      refreshToken.CreatedAt,
		Revoked:        refreshToken.Revoked,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)), //24小时以后过期
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

	return authToken.AuthTokenID, nil
}

// Authorize validates the browser's OIDC authorization request and saves the
// result until the user submits credentials to Login.
// Get请求用bindquery，Post请求用ShouldBindJSON
// 这步不带secret， accesstoken时才带
// codechallenge校验verifier在exchange，nonce在token中
func (h *AuthHandler) Authorize(c *gin.Context) {
	var req struct {
		ResponseType        string `form:"response_type" binding:"required"`
		ClientID            string `form:"client_id" binding:"required"`
		RedirectURI         string `form:"redirect_uri" binding:"required"`
		Scope               string `form:"scope" binding:"required"`
		State               string `form:"state"`
		Nonce               string `form:"nonce"`
		CodeChallenge       string `form:"code_challenge"`
		CodeChallengeMethod string `form:"code_challenge_method"`
	}
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ResponseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only response_type=code is supported"})
		return
	}

	client, err := h.clientService.GetClientByID(c.Request.Context(), req.ClientID)
	if err != nil || !client.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client_id"})
		return
	}
	if client.RedirectURI != req.RedirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri does not match client registration"})
		return
	}
	requestedScopes := strings.Fields(req.Scope)
	if !containsScope(requestedScopes, "openid") || !scopesAllowed(requestedScopes, client.AllowedScopes) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope"})
		return
	}
	err = validatePKCE(req.CodeChallenge, req.CodeChallengeMethod)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("PKCE error occurred: %v", err)})
		return
	}
	claims := authorizationRequestClaims{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	requestToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(h.authService.GetSecretKey()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create authorization request"})
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authorizationRequestCookie, requestToken, 300, "/auth", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "authorization request accepted; submit credentials to /auth/login"})
}

// POST /auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		ClientID            string `json:"client_id" binding:"required"`
		LoginID             string `json:"login_id" binding:"required"`
		Password            string `json:"password" binding:"required"`
		RedirectURI         string `json:"redirect_uri" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	authorizationRequest, err := h.getAuthorizationRequest(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "valid authorization request is required"})
		return
	}
	if authorizationRequest.ClientID != req.ClientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the client in cookie and rquest is not equal"})
		return
	}
	session, err := h.authService.Login(c.Request.Context(), req.LoginID, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	authToken, err := h.authService.CreateAuthToken(c.Request.Context(), session.UserID, authorizationRequest.RedirectURI, authorizationRequest.ClientID, authorizationRequest.CodeChallenge, authorizationRequest.CodeChallengeMethod)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	token_id, err := h.generateAuthToken(authToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.SetCookie(authorizationRequestCookie, "", -1, "/auth", "", false, true)
	c.JSON(http.StatusOK, gin.H{"code": token_id, "session_id": session.SessionID, "expires_in": 300})
}

func (h *AuthHandler) getAuthorizationRequest(c *gin.Context) (*authorizationRequestClaims, error) {
	requestToken, err := c.Cookie(authorizationRequestCookie)
	if err != nil {
		return nil, err
	}
	parsedToken, err := jwt.ParseWithClaims(requestToken, &authorizationRequestClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected authorization request signing method")
		}
		return []byte(h.authService.GetSecretKey()), nil
	})
	if err != nil || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid authorization request")
	}
	claims, ok := parsedToken.Claims.(*authorizationRequestClaims)
	if !ok {
		return nil, fmt.Errorf("invalid authorization request claims")
	}
	return claims, nil
}

func containsScope(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

func scopesAllowed(requestedScopes, allowedScopes []string) bool {
	for _, scope := range requestedScopes {
		if !containsScope(allowedScopes, scope) {
			return false
		}
	}
	return true
}

// POST /auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// 必须大写，大写才会被解析
	var req struct {
		SessionID string `json:"session_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Logout 会通过sessionID注销session和token
	err := h.authService.Logout(c.Request.Context(), req.SessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Logout successfully"})
}

// POST /auth/token
func (h *AuthHandler) ExchangeToken(c *gin.Context) {
	var req struct {
		GrantType    string `json:"grant_type" binding:"required"`
		ClientID     string `json:"client_id" binding:"required"`
		AuthToken    string `json:"code" binding:"required"`
		RedirectURI  string `json:"redirect_uri" binding:"required"`
		ClientSecret string `json:"client_secret" `
		CodeVerifier string `json:"code_verifier" `
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	accessToken, err := h.authService.ExchangeAuthToken(c.Request.Context(), req.AuthToken, req.RedirectURI, req.ClientID, req.CodeVerifier)
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
	if err := c.ShouldBindJSON(&req); err != nil {
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
	if err := c.ShouldBindJSON(&req); err != nil {
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
	if err := c.ShouldBindJSON(&req); err != nil {
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
	if err := c.ShouldBindJSON(&req); err != nil {
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
	if err := c.ShouldBindJSON(&req); err != nil {
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

// private function
// codechallenge是verifier做哈希出来再base64url编码的结果,所以是43字符
// plain格式就是不编码
func validatePKCE(codeChallenge string, method string) error {
	if codeChallenge == "" {
		return fmt.Errorf("codeChallenge is required")
	}
	if method == "" {
		return fmt.Errorf("method is required")
	}
	switch method {
	case "S256":
		// BASE64URL(SHA256(verifier))，43 个字符
		if len(codeChallenge) != 43 {
			return fmt.Errorf("invalid code challenge for S256")
		}
		if _, err := base64.RawURLEncoding.DecodeString(codeChallenge); err != nil {
			return fmt.Errorf("invalid code_challenge encoding")
		}
	case "plain":
		if len(codeChallenge) < 43 || len(codeChallenge) > 128 {
			return fmt.Errorf("invalid code challenge for plain")
		}
	default:
		return fmt.Errorf("invalid code challenge method")
	}
	return nil
}
