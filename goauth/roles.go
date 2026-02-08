package goauth

import "github.com/Des1red/goauthlib/internal/tokens"

func RoleAnonymous() string {
	return tokens.RoleAnonymous()
}

func RoleUser() string {
	return tokens.RoleUser()
}

func RoleAdmin() string {
	return tokens.RoleAdmin()
}
