package service

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"gin-demo/internal/user/repository"
	"os"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)



type IDTokenClaims struct {
	Nonce             string `json:"nonce,omitempty"`
	AuthTime          int64  `json:"auth_time,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	jwt.RegisteredClaims
}

func (i *SigningKey) SignIDToken(user *repository.User, clientID string, scopes []string, nonce string, authTime int64) (string, error) {

	claims := i.buildClaims(user, clientID, scopes, nonce, authTime)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = i.KeyID //设置头部key id

	return tok.SignedString(i.PrivateKey) //基于私钥签名的idtoken claims，返回签名后的token字符串
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

func (i *SigningKey) buildClaims(user *repository.User, clientID string, scopes []string, nonce string, authTime int64) IDTokenClaims {
	claims := IDTokenClaims{
		Nonce:    nonce,
		AuthTime: authTime,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.Issuer,
			Subject:   user.UserID,                                           //唯一标识
			Audience:  jwt.ClaimStrings{clientID},                            //客户端id
			IssuedAt:  jwt.NewNumericDate(time.Now()),                        //签发时间
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),     //过期时间
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Second * 20)), //生效时间
			
		},
	}
	if slices.Contains(scopes, "email") {
		claims.Email = user.Email
		claims.EmailVerified = true
	}
	if slices.Contains(scopes, "profile") {
		claims.Name = user.Username
		claims.PreferredUsername = user.Username
	}

	return claims
}
