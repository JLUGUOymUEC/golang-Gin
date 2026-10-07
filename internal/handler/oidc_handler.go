package handler

import (
	"encoding/base64"
	"gin-demo/internal/user/service"
	"math/big"

	"github.com/gin-gonic/gin"
)

type OIDCHandler struct {
	issuer        string              //  discovery 用
	idTokenIssuer *service.SigningKey // jwks 用
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

func NewOIDCHandler(issuer string, idTokenIssuer *service.SigningKey) *OIDCHandler {
	return &OIDCHandler{
		issuer:        issuer,
		idTokenIssuer: idTokenIssuer,
	}
}

// 目的是把公钥暴露给SP
func buildJWKS(key *service.SigningKey) jwksResponse {
	publicKey := key.PublicKey()
	// 签名：sig = padded_hash ^ d  mod n d是私钥指数
	// padded_hash = sig ^ e  mod n      sig是签名
	return jwksResponse{
		Keys: []jwk{{
			Kty: "RSA",                                                                        //加密方式 key type
			Use: "sig",                                                                        //用途 sig是验签 enc是加密
			Alg: "RS256",                                                                      //intended algorithm
			Kid: key.KeyID,                                                                    //标记密钥位置
			N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),                    //公钥模数
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()), //公钥指数
		},
		},
	}
}

func (h *OIDCHandler) Discovery(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600") //可以缓存，但是设置上限时间，防止密钥轮换后，客户端还在用旧的缓存
	c.JSON(200, gin.H{
		"issuer":                                h.issuer,
		"authorization_endpoint":                h.issuer + "/auth/authorize",
		"jwks_uri":                              h.issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"}, //不支持隐式模式
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint":                        h.issuer + "/auth/token",
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		// "userinfo_endpoint":                     h.issuer + "/api/v1/user/me",
	})
}

func (h *OIDCHandler) JWKS(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600") //可以缓存，但是设置上限时间，防止密钥轮换后，客户端还在用旧的缓存
	c.JSON(200, buildJWKS(h.idTokenIssuer))
}
