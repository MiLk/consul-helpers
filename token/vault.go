package token

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/hashicorp/vault/api"
)

func (t *Token) getConsulTokenFromVault(role string) (string, error) {
	config := api.DefaultConfig()
	client, err := api.NewClient(config)
	if err != nil {
		return "", errors.Wrap(err, "creating vault client")
	}

	vaultToken, err := t.strategy.GetVaultToken(client, role)
	if err != nil {
		return "", errors.Wrap(err, "retrieving vault token")
	}

	client.SetToken(vaultToken)

	secret, err := client.Logical().Read(fmt.Sprintf("/consul/creds/%s", role))
	if err != nil {
		return "", errors.Wrap(err, "fetching consul credentials")
	}

	token, ok := secret.Data["token"]
	if !ok {
		return "", errors.New("Unable to get a new Consul token.")
	}

	tokenStr, ok := token.(string)
	if !ok {
		return "", errors.New("Unable to get a new Consul token.")
	}

	return tokenStr, nil
}
