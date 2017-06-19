package token

import (
	"encoding/base64"
	"net"
	"os"
	"testing"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/testutil"
	vaultapi "github.com/hashicorp/vault/api"
	logicalconsul "github.com/hashicorp/vault/builtin/logical/consul"
	"github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/vault"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func setupConsulWithVault(t *testing.T) (*testutil.TestServer, net.Listener, string, error) {
	server, err := testutil.NewTestServerConfig(func(c *testutil.TestServerConfig) {
		c.Datacenter = "dc1"
		c.ACLMasterToken = "acl_master_token"
		c.ACLDatacenter = "dc1"
		c.ACLDefaultPolicy = "allow"
		c.ACLEnforceVersion8 = true
	})
	if err != nil {
		return nil, nil, "", errors.Wrap(err, "new consul test server")
	}

	vault.AddTestLogicalBackend("consul", logicalconsul.Factory)
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := http.TestServer(t, core)

	os.Setenv("VAULT_ADDR", addr)

	client, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return server, ln, token, errors.Wrap(err, "new vault client")
	}

	client.SetToken(token)

	if err := client.Sys().Mount("consul", &vaultapi.MountInput{
		Type: "consul",
	}); err != nil {
		return server, ln, token, errors.Wrap(err, "mounting consul secret backend")
	}

	if _, err := client.Logical().Write("consul/config/access", map[string]interface{}{
		"address": server.HTTPAddr,
		"token":   "acl_master_token",
	}); err != nil {
		return server, ln, token, errors.Wrap(err, "configuring consul secret backend")
	}

	policy := base64.StdEncoding.EncodeToString([]byte(`key "foo/" { policy = "write" }`))
	if _, err := client.Logical().Write("consul/roles/foo", map[string]interface{}{
		"token_type": "client",
		"lease":      "1h",
		"policy":     policy,
	}); err != nil {
		return server, ln, token, errors.Wrap(err, "adding the foo policy to the consul secret backend")
	}

	return server, ln, token, nil
}

func TestNewToken(t *testing.T) {
	server, vaultLn, vaultToken, err := setupConsulWithVault(t)
	if vaultLn != nil {
		defer vaultLn.Close()
	}
	if server != nil {
		defer server.Stop()
	}
	assert.Nil(t, err)

	client, err := api.NewClient(&api.Config{
		HttpClient: server.HTTPClient,
		Address:    server.HTTPAddr,
		Scheme:     "http",
	})

	// Renew then get the string
	token := NewToken(client, "foo", &StaticStrategy{
		Token: vaultToken,
	})
	assert.False(t, token.IsValid())
	assert.Nil(t, token.Renew())
	assert.True(t, token.IsValid())
	assert.NotEmpty(t, token.String())
	assert.True(t, token.IsValid())

	// Get the string without renew
	token = NewToken(client, "foo", &StaticStrategy{
		Token: vaultToken,
	})
	assert.False(t, token.IsValid())
	assert.NotEmpty(t, token.String())
	assert.True(t, token.IsValid())

	// No consul client
	token = NewToken(nil, "foo", &StaticStrategy{
		Token: vaultToken,
	})
	assert.False(t, token.IsValid())
	assert.Empty(t, token.String())
	assert.False(t, token.IsValid())

	// Invalid vault token
	token = NewToken(client, "foo", &StaticStrategy{
		Token: "",
	})
	assert.False(t, token.IsValid())
	assert.NotNil(t, token.Renew())

	// Invalid role
	token = NewToken(client, "bar", &StaticStrategy{
		Token: vaultToken,
	})
	assert.False(t, token.IsValid())
	assert.NotNil(t, token.Renew())

	// Empty token
	token = NewToken(client, "", nil)
	assert.False(t, token.IsValid())
	assert.Nil(t, token.Renew())
	assert.Empty(t, token.String())
}
