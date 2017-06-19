package token

import "github.com/hashicorp/vault/api"

type Strategy interface {
	GetVaultToken(client *api.Client, role string) (string, error)
}
