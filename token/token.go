package token

import (
	consulapi "github.com/hashicorp/consul/api"
)

type Token struct {
	consul   *consulapi.Client
	token    string
	role     string
	strategy Strategy
}

func NewToken(consul *consulapi.Client, role string, s Strategy) *Token {
	return &Token{
		consul:   consul,
		role:     role,
		strategy: s,
	}
}

func (t *Token) IsValid() bool {
	if t.token == "" {
		return false
	}

	acl, _, _ := t.consul.ACL().Info(t.token, nil)
	return acl != nil
}

func (t *Token) Renew() error {
	if t.role == "" {
		return nil
	}

	token, err := t.getConsulTokenFromVault(t.role)
	if err != nil {
		return err
	}
	t.token = token
	return nil
}

func (t *Token) String() string {
	if t.consul == nil {
		return ""
	}

	if !t.IsValid() {
		t.Renew()
	}
	return t.token
}
