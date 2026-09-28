package service

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"gin-demo/internal/user/repository"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type IDTokenIssuer struct {
	issuer         string
	keyID          string
	privateKey     *rsa.PrivateKey
	SessionService *SessionService
}

type IDTokenIssuerConfig struct {
	Issuer         string
	KeyID          string
	PrivateKeyPath string
}

type IDTokenClaims struct {
	Nonce             string `json:"nonce,omitempty"`
	AuthTime          int64  `json:"auth_time,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	jwt.RegisteredClaims
}

func NewIDTokenIssuer(cfg IDTokenIssuerConfig) (*IDTokenIssuer, error) {
	privateKey, err := loadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	return &IDTokenIssuer{
		issuer:     cfg.Issuer,
		keyID:      cfg.KeyID,
		privateKey: privateKey,
	}, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)                     // 解码 PEM 格式的私钥，block形式的结构体中bytes字段就是私钥的字节流
	if block == nil || block.Type != "PRIVATE KEY" { // 检查PKCS#8 格式
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes) // 解析 PKCS#8 格式的 RSA 私钥 现在的格式是PKCS#8
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an RSA key")
	}
	return rsaKey, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (i *IDTokenIssuer) SignIDToken(user *repository.User, clientID string, scopes []string, nonce string, authTime int64) (string, error) {

	claims := i.buildClaims(user, clientID, scopes, nonce, authTime)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = i.keyID //设置头部key id

	return tok.SignedString(i.privateKey) //基于私钥签名的idtoken claims，返回签名后的token字符串
}

func (i *IDTokenIssuer) buildClaims(user *repository.User, clientID string, scopes []string, nonce string, authTime int64) IDTokenClaims {
	claims := IDTokenClaims{
		Nonce:    nonce,
		AuthTime: authTime,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   user.UserID,                                           //唯一标识
			Audience:  jwt.ClaimStrings{clientID},                            //客户端id
			IssuedAt:  jwt.NewNumericDate(time.Now()),                        //签发时间
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),     //过期时间
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Second * 20)), //生效时间
		},
	}
	if contains(scopes, "email") {
		claims.Email = user.Email
		claims.EmailVerified = true
	}
	if contains(scopes, "profile") {
		claims.Name = user.Username
		claims.PreferredUsername = user.Username
	}

	return claims
}

func (i *IDTokenIssuer) PublicKey() *rsa.PublicKey {
	return &i.privateKey.PublicKey
}

func (i *IDTokenIssuer) GetKeyID() string {
	return i.keyID
}

func (i *IDTokenIssuer) GetIssuer() string {
	return i.issuer
}
