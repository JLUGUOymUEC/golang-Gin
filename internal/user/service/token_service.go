package service

import (
	"crypto/rsa"
	"fmt"
)

// idtoken accesstoken 类
type SigningKey struct {
	Issuer     string
	KeyID      string
	PrivateKey *rsa.PrivateKey
}

type TokenIssuerConfig struct {
	Issuer         string
	KeyID          string
	PrivateKeyPath string
}

func NewSigningKey(cfg TokenIssuerConfig) (*SigningKey, error) {
	PrivateKey, err := loadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	return &SigningKey{
		Issuer:     cfg.Issuer,
		KeyID:      cfg.KeyID,
		PrivateKey: PrivateKey,
	}, nil
}

func (i *SigningKey) PublicKey() *rsa.PublicKey {
	return &i.PrivateKey.PublicKey
}

// func (i *SigningKey) GetKeyID() string {
// 	return i.KeyID
// }

// func (i *SigningKey) GetIssuer() string {
// 	return i.Issuer
// }
