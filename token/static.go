package token

import "github.com/hashicorp/vault/api"

type StaticStrategy struct {
	Token string
}

func (s *StaticStrategy) GetVaultToken(client *api.Client, role string) (string, error) {
	return s.Token, nil
}
