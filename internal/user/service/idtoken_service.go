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
	issuer     string
	keyID      string
	privateKey *rsa.PrivateKey
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

func NewIDTokenIssuer(issuer, keyID, privateKeyPath string) (*IDTokenIssuer, error) {
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	return &IDTokenIssuer{
		issuer:     issuer,
		keyID:      keyID,
		privateKey: privateKey,
	}, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data) // 解码 PEM 格式的私钥，block形式的结构体中bytes字段就是私钥的字节流
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes) // 解析 PKCS#1 格式的 RSA 私钥
	if err != nil {
		return nil, err
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
	if !contains(scopes, "profile") {
		return "", errors.New("profile is required for the requested scopes")
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(i.privateKey) //基于私钥签名的idtoken claims，返回签名后的token字符串
}

func (i *IDTokenIssuer) buildClaims(user *repository.User, clientID string, scopes []string, nonce string, authTime int64) IDTokenClaims {
	claims := IDTokenClaims{
		Nonce:    nonce,
		AuthTime: authTime,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   user.UserID,                                       //唯一标识
			Audience:  jwt.ClaimStrings{clientID},                        //客户端id
			IssuedAt:  jwt.NewNumericDate(time.Now()),                    //签发时间
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)), //过期时间
			NotBefore: jwt.NewNumericDate(time.Now()),                    //生效时间
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
