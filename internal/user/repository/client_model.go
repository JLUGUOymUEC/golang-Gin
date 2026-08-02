package repository

import "fmt"

type OAuthClient struct {
	ClientID          string   `dynamodbav:"client_id"`
	ClientSecretHash  string   `dynamodbav:"client_secret_hash"`
	AppName           string   `dynamodbav:"name"`
	RedirectURI       string   `dynamodbav:"redirect_uri"`
	AllowedGrantTypes []string `dynamodbav:"allowed_grant_types"`
	AllowedScopes     []string `dynamodbav:"allowed_scopes"`

	IsActive  bool  `dynamodbav:"is_active"`
	CreatedAt int64 `dynamodbav:"created_at"`
	UpdatedAt int64 `dynamodbav:"updated_at"`
}

type GrantType string

const (
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantRefreshToken      GrantType = "refresh_token"
)

type Scope string

const (
	ScopeOpenID  Scope = "openid"
	ScopeProfile Scope = "profile"
	ScopeEmail   Scope = "email"
)

func DefaultGrantTypes() []string {
	return []string{
		string(GrantAuthorizationCode),
		string(GrantRefreshToken),
	}
}

func DefaultGrantScopes() []string {
	return []string{
		string(ScopeOpenID),
		string(ScopeProfile),
		string(ScopeEmail),
	}
}

func IsSupportedGrantType(grantType string) bool {
	switch GrantType(grantType) {
	case GrantAuthorizationCode, GrantRefreshToken:
		return true
	default:
		return false
	}
}

func IsSupportedScope(scope string) bool {
	switch Scope(scope) {
	case ScopeOpenID, ScopeProfile, ScopeEmail:
		return true
	default:
		return false
	}
}

func ValidateGrantTypes(grantTypes []string) error {
	for _, grantType := range grantTypes {
		if !IsSupportedGrantType(grantType) {
			return fmt.Errorf("unsupported grant type: %s", grantType)
		}
	}
	return nil
}

func ValidateGrantScopes(grantScopes []string) error {
	for _, grantScope := range grantScopes {
		if !IsSupportedScope(grantScope) {
			return fmt.Errorf("unsupported grant scope: %s", grantScope)
		}
	}
	return nil
}
