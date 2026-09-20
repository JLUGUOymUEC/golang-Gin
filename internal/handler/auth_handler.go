package handler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"gin-demo/internal/gateway/middleware"
	"gin-demo/internal/user/repository"
	"gin-demo/internal/user/service"
	"net/http"
	"net/url"
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
		ClientID    string `json:"client_id" binding:"required"`
		LoginID     string `json:"login_id" binding:"required"`
		Password    string `json:"password" binding:"required"`
		RedirectURI string `json:"redirect_uri" binding:"required"` // "https://client.example.com/cb?foo=bar"
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
	//保证授权请求中的redirectURI一致
	if authorizationRequest.RedirectURI != req.RedirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the redirect_uri in cookie and rquest is not equal"})
		return
	}
	client, err := h.clientService.GetClientByID(c.Request.Context(), req.ClientID)
	if client.RedirectURI != req.RedirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the redirect_uri in cookie and client is not equal"})
		return
	}
	session, err := h.authService.Login(c.Request.Context(), req.LoginID, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	authToken, err := h.authService.CreateAuthToken(c.Request.Context(), session.UserID, authorizationRequest.RedirectURI, authorizationRequest.ClientID, authorizationRequest.CodeChallenge, authorizationRequest.CodeChallengeMethod, session.SessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	token_id, err := h.generateAuthToken(authToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	redirectURL, err := url.Parse(authorizationRequest.RedirectURI) // 把真正的uri拆出来
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	q := redirectURL.Query()
	q.Set("code", token_id)                    // 通过这个方式把code传给client
	q.Set("state", authorizationRequest.State) // CSRF防护，原样回传
	redirectURL.RawQuery = q.Encode()          //先setcookie，再302跳转，浏览器会带上cookie
	c.SetCookie(authorizationRequestCookie, "", -1, "/auth", "", false, true)
	c.SetCookie("session_id", session.SessionID, 300, "/", "", false, true)
	c.Redirect(http.StatusFound, redirectURL.String()) // 返回302
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

	// user_id 只能来自已验签的 JWT（AuthMiddleware 写入），不能从请求体接收。
	userID, ok := middleware.GetCurrentUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	// session_id 是 bearer 值，必须先确认它属于当前登录用户，
	// 否则任何登录用户都能用别人的 session_id 把别人登出。
	if err := h.authService.ValidateSessionOwnership(c.Request.Context(), userID, req.SessionID); err != nil {
		if errors.Is(err, service.ErrSessionNotOwned) {
			c.JSON(http.StatusForbidden, gin.H{"error": "session does not belong to you"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
		return
	}

	// 撤销该用户全部凭证：access token + refresh token + session
	if err := h.authService.RevokeAllUserCredentials(c.Request.Context(), userID); err != nil {
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
	if req.GrantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid grant_type"})
		return
	}
	clientID, ok := middleware.GetClientID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if clientID != req.ClientID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "client_id error"})
		return
	}
	accessToken, session_id, err := h.authService.ExchangeAuthToken(c.Request.Context(), req.AuthToken, req.RedirectURI, req.ClientID, req.CodeVerifier)
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
	if err = h.accountService.SessionService.BindTokens(c.Request.Context(), session_id, accessToken.AccessTokenID, refreshToken.RefreshTokenID); err != nil {
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
	sessionID, ok := middleware.GetSessionID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	//防止重放攻击，需要先revoke当前的refreshtoken
	accessToken, err := h.authService.RefreshAccessToken(c.Request.Context(), req.RefreshToken, sessionID)
	if err != nil {
		// refresh token 不存在/已撤销/并发竞争失败都归为 401，不是服务端错误
		if errors.Is(err, service.ErrRefreshTokenInvalid) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token is invalid or already used"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	// 轮换一个refreshToken
	// 旧的 refresh token 已在 RefreshAccessToken 内原子撤销，这里不再重复撤销
	newRefreshToken, err := h.authService.CreateRefreshToken(c.Request.Context(), accessToken.UserID)
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
	if err = h.accountService.SessionService.BindTokens(c.Request.Context(), sessionID, accessToken.AccessTokenID, newRefreshToken.RefreshTokenID); err != nil {
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
