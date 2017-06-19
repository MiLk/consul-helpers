package token

import (
	"testing"

	httpmock "gopkg.in/jarcoal/httpmock.v1"

	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/stretchr/testify/assert"

	"os"

	"net"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/logical/aws"
	"github.com/hashicorp/vault/vault"
	"github.com/pkg/errors"
)

func setupVaultWithFakeMetadataServer(t *testing.T) (net.Listener, error) {
	vault.AddTestLogicalBackend("aws-ec2", aws.Factory)
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := vaulthttp.TestServer(t, core)

	os.Setenv("VAULT_ADDR", addr)

	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return ln, errors.Wrap(err, "new vault client")
	}

	client.SetToken(token)

	if err := client.Sys().EnableAuth("aws-ec2", "aws-ec2", "aws-ec2"); err != nil {
		return ln, err
	}

	if _, err := client.Logical().Write("auth/aws-ec2/role/foo", map[string]interface{}{
		"role":      "foo",
		"auth_type": "ec2",
	}); err != nil {
		return ln, err
	}

	return ln, nil
}

func TestNewEC2Strategy(t *testing.T) {
	ln, err := setupVaultWithFakeMetadataServer(t)
	defer ln.Close()
	assert.Nil(t, err)

	client, err := api.NewClient(api.DefaultConfig())
	assert.Nil(t, err)

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "http://169.254.169.254/latest/dynamic/instance-identity/pkcs7",
		httpmock.NewStringResponder(200, ``))

	s := NewEC2Strategy(WithNonce("nonce"))
	token, err := s.GetVaultToken(client, "foo")
	assert.Nil(t, err)
	assert.NotEmpty(t, token)
}
