package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"gin-demo/internal/user/repository"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrRefreshTokenInvalid 是 refresh token 不可用的统一出口（不存在、已撤销、并发竞争失败）。
// handler 据此回 401，而不是把它当成服务端错误。
var ErrRefreshTokenInvalid = errors.New("refresh token is invalid or already used")

// ErrSessionNotOwned 表示该 session 不属于当前已认证用户。
var ErrSessionNotOwned = errors.New("session does not belong to the authenticated user")

// classifyRefreshTokenRevokeErr 把仓储层的撤销错误映射成对外统一语义。
func classifyRefreshTokenRevokeErr(err error) error {
	if errors.Is(err, repository.ErrRefreshTokenAlreadyRevoked) ||
		errors.Is(err, repository.ErrRefreshTokenNotFound) {
		return ErrRefreshTokenInvalid
	}
	return fmt.Errorf("Failed to revoke refresh token: %w ", err)
}

// type AuthService interface {
//     // 授权码流程
//     CreateAuthCode(ctx context.Context, userID, redirectURI string) (*AuthorizeToken, error)

//     // Token 操作
//     ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error)
//     RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)
//     RevokeToken(ctx context.Context, tokenString string) error
// }

type AuthService struct {
	userRepo         repository.UserRepository
	sessionServce    *SessionService
	authTokenRepo    repository.AuthTokenRepository
	accessTokenRepo  repository.AccessTokenRepository
	refreshTokenRepo repository.RefreshTokenRepository
	clientRepo       repository.ClientRepository
	secret           string
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
	SessionID      string `json:"session_id"`
	jwt.RegisteredClaims
}

func (service *AuthService) GetSecretKey() string {
	return service.secret
}

func NewAuthService(userRepo repository.UserRepository, sessionService *SessionService, authTokenRepo repository.AuthTokenRepository, accessTokenRepo repository.AccessTokenRepository, refreshTokenRepo repository.RefreshTokenRepository, clientRepo repository.ClientRepository, secret string) *AuthService {
	return &AuthService{
		userRepo:         userRepo,
		sessionServce:    sessionService,
		authTokenRepo:    authTokenRepo,
		accessTokenRepo:  accessTokenRepo,
		refreshTokenRepo: refreshTokenRepo,
		clientRepo:       clientRepo,
		secret:           secret,
	}
}

func (service *AuthService) CreateRefreshToken(ctx context.Context, userID string) (*repository.RefreshToken, error) {
	refreshToken := &repository.RefreshToken{
		UserID: userID,
	}
	refreshToken.BeforeCreate()
	err := service.refreshTokenRepo.CreateToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to create refresh token: %w ", err)
	}
	if err := refreshToken.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid refresh token data: %w ", err)
	}
	return refreshToken, nil
}

func (service *AuthService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(service.secret), nil
	})
	if err != nil || !token.Valid {
		return fmt.Errorf("Invalid token: %w ", err)
	}
	if claims, ok := token.Claims.(*RefreshTokenClaims); ok {
		return service.refreshTokenRepo.RevokeToken(ctx, claims.RefreshTokenID)
	}

	return fmt.Errorf("Failed to revoke token: %w ", err)
}

func (service *AuthService) CreateAuthToken(ctx context.Context, userID string , redirectURI string, clientID string, codeChallenge string, codeChallengeMethod string ,sessionID string) (*repository.AuthorizeToken, error) {
	authToken := &repository.AuthorizeToken{
		UserID: userID,
		RedirectURI: redirectURI,
		ClientID:  clientID,
		CodeChallenge: codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Revoked:  false,
		SessionID: sessionID,
	}
	authToken.BeforeCreate()
	if err := authToken.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid auth code data: %w ", err)
	}
	err := service.authTokenRepo.CreateToken(ctx, authToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to create auth code: %w ", err)
	}
	return authToken, nil //handler里要把token转为字符串返回给客户端
}

func (service *AuthService) ExchangeAuthToken(ctx context.Context, authTokenID string, RedirectURI string, clientID string, codeVerifier string) (*repository.AccessToken,string, error) {

	authToken, err := service.authTokenRepo.GetTokenByID(ctx, authTokenID)
	if err != nil {
		return nil,"", fmt.Errorf("Failed to get auth token: %w ", err)
	}
	if err = authToken.Validate(); err != nil {
		return nil,"", fmt.Errorf("Invalid auth token: %w ", err)
	}
	if ok := verifyPKCE(codeVerifier, authToken.CodeChallenge, authToken.CodeChallengeMethod); !ok{
		return nil,"", fmt.Errorf("Invalid codeVerifier: %w ", err)
	}
	client, err := service.clientRepo.GetClientByID(ctx, clientID)
	if err != nil || client == nil || client.IsActive == false {
		return nil,"", fmt.Errorf("Invalid client_id")
	}

	if authToken.Revoked {
		return nil,"", fmt.Errorf("Auth token is revoked")
	}
	if authToken.RedirectURI != RedirectURI {
		return nil,"", fmt.Errorf("Redirect URI does not match")
	}
	accessToken := &repository.AccessToken{
		UserID:  authToken.UserID,
		Revoked: false,
	}
	accessToken.BeforeCreate()
	if err := accessToken.Validate(); err != nil {
		return nil,"", fmt.Errorf("Invalid access token data: %w ", err)
	}
	if err := service.accessTokenRepo.CreateToken(ctx, accessToken); err != nil {
		return nil,"", fmt.Errorf("Failed to create access token: %w ", err)
	}
	if err := service.authTokenRepo.RevokeToken(ctx, authTokenID); err != nil {
		return nil,"", fmt.Errorf("Failed to revoke access token: %w ", err)
	}
	return accessToken,authToken.SessionID, nil
}

func (service *AuthService) ValidateAccessToken(ctx context.Context, accessToken string) (*AccessTokenClaims, error) {
	//eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIiwic2Vzc2lvbl9pZCI6Inh4eCIsImV4cCI6MTY5OTk5OTk5OX0.signature
	// ↑ Header                            ↑ Payload (claims)                  ↑ Signature
	// 使用·jwt库解析和验证Token 第三个参数是给一个回调方法去验签,token是使用accessToken解析出的信息去构成的
	token, err := jwt.ParseWithClaims(accessToken, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		//判断是不是对称SHA256加密算法
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected alg: %v", token.Method.Alg())
		}
		return []byte(service.secret), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("Invalid token: %w ", err)
	}
	if claims, ok := token.Claims.(*AccessTokenClaims); ok {
		saved_token, err := service.accessTokenRepo.GetTokenByID(ctx, claims.AccessTokenID)
		if err != nil || saved_token == nil || saved_token.TTL <= time.Now().Unix() || saved_token.Revoked || saved_token.UserID != claims.UserID {
			return nil, fmt.Errorf("Access token is invalid or revoked")
		}
		return claims, nil
	}
	return nil, fmt.Errorf("Failed to valid token: %w ", err)
}

func (service *AuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (*repository.AccessToken, error) {
	accessToken := &repository.AccessToken{}

	token, err := jwt.ParseWithClaims(refreshToken, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected alg: %v", token.Method.Alg())
		}
		return []byte(service.secret), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("Invalid refresh token: %w ", err)
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok {
		return nil, fmt.Errorf("Invalid refresh token claims")
	}
	refreshTokenRecord, err := service.refreshTokenRepo.GetTokenByID(ctx, claims.RefreshTokenID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get refresh token: %w ", err)
	}
	if refreshTokenRecord.Validate() != nil || refreshTokenRecord.Revoked {
		return nil, ErrRefreshTokenInvalid
	}

	// 关键：先原子地占用（撤销）这个 refresh token，再做后续副作用。
	// 条件写的是"存在且 revoked = false"，所以并发请求里只有一个能成功，
	// 其余会拿到 ErrRefreshTokenInvalid，不会各自签出一套 token。
	if err := service.refreshTokenRepo.RevokeToken(ctx, claims.RefreshTokenID); err != nil {
		return nil, classifyRefreshTokenRevokeErr(err)
	}

	// 按 user_id 撤销该用户此前所有 access token（Route A：一个用户可以并存多套）
	if err := service.accessTokenRepo.RevokeAllByUserID(ctx, claims.UserID); err != nil {
		return nil, fmt.Errorf("Failed to revoke previous access tokens: %w ", err)
	}

	accessToken.UserID = claims.UserID
	accessToken.BeforeCreate()
	if err := accessToken.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid access token data: %w ", err)
	}
	if err := service.accessTokenRepo.CreateToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("Failed to create access token: %w ", err)
	}
	return accessToken, nil
}

func (service *AuthService) RevokeAccessToken(ctx context.Context, accessToken string) error {

	token, err := jwt.ParseWithClaims(accessToken, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected alg: %v", token.Method.Alg())
		}
		return []byte(service.secret), nil
	})
	if err != nil || !token.Valid {
		return fmt.Errorf("Invalid token: %w ", err)
	}
	if claims, ok := token.Claims.(*AccessTokenClaims); ok {
		return service.accessTokenRepo.RevokeToken(ctx, claims.AccessTokenID)
	}
	return fmt.Errorf("Failed to revoke token: %w ", err)
}

func (service *AuthService) Login(ctx context.Context, loginID string, password string) (*repository.Session, error) {
	user, err := service.userRepo.GetUserByEmail(ctx, loginID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get user by email: %w ", err)
	}
	if user == nil {
		user, err = service.userRepo.GetUserByUsername(ctx, loginID)
		if err != nil {
			return nil, fmt.Errorf("Failed to get user by username: %w ", err)
		}
		if user == nil {
			return nil, fmt.Errorf("user not found")
		}
	}
	if !VerifyPassword(password, user.HashedPassword) {
		return nil, fmt.Errorf("Invalid password for user with email %s", loginID)
	}
	session, err := service.sessionServce.CreateSession(ctx, user.UserID)
	if err != nil {
		return nil, fmt.Errorf("Failed to create session: %w ", err)
	}
	return session, nil
}

func (service *AuthService) Logout(ctx context.Context, sessionID string) error {
	return service.sessionServce.RevokeSession(ctx, sessionID)
}

// ValidateSessionOwnership 校验 sessionID 属于 authenticatedUserID。
// session_id 在 API 里是明文传递的 bearer 值，没有绑定调用方凭证，
// 所以任何"按 session 操作"的入口都必须先过这一步，否则会变成登出任意用户。
func (service *AuthService) ValidateSessionOwnership(ctx context.Context, authenticatedUserID, sessionID string) error {
	session, err := service.sessionServce.ValidateSession(ctx, sessionID)
	if err != nil {
		return err
	}
	if session.UserID != authenticatedUserID {
		return ErrSessionNotOwned
	}
	return nil
}

// RevokeAllUserCredentials 撤销该用户当前所有 access token、refresh token 和 session。
// 用于登出与改密码——两处都需要"该用户全部凭证立即失效"。
func (service *AuthService) RevokeAllUserCredentials(ctx context.Context, userID string) error {
	if err := service.accessTokenRepo.RevokeAllByUserID(ctx, userID); err != nil {
		return fmt.Errorf("Failed to revoke access tokens: %w ", err)
	}
	if err := service.refreshTokenRepo.RevokeAllByUserID(ctx, userID); err != nil {
		return fmt.Errorf("Failed to revoke refresh tokens: %w ", err)
	}
	sessionIDs, err := service.sessionServce.GetSessionIDsByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("Failed to get user sessions: %w ", err)
	}
	for _, sessionID := range sessionIDs {
		if err := service.sessionServce.RevokeSession(ctx, sessionID); err != nil {
			return fmt.Errorf("Failed to revoke session: %w ", err)
		}
	}
	return nil
}



func verifyPKCE(verifier string, challenge string, method string) bool {
	switch method {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		// []byte转切片 sum[0:]
		expected := base64.RawURLEncoding.EncodeToString(sum[0:])
		return subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
	case "plain":
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	}
	return false
}
