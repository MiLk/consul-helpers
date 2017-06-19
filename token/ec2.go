package token

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
)

type EC2Strategy struct {
	nonce string
}

func getNonce(path string) (string, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(content)), nil
}

func NewEC2Strategy(opts ...func(s *EC2Strategy)) *EC2Strategy {
	s := EC2Strategy{}
	for _, opt := range opts {
		opt(&s)
	}
	if s.nonce == "" {
		s.nonce, _ = getNonce("/etc/vault-nonce")
	}
	return &s
}

func WithNonce(n string) func(s *EC2Strategy) {
	return func(s *EC2Strategy) { s.nonce = n }
}

func (s *EC2Strategy) getPkcs7() (string, error) {
	resp, err := http.Get("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.Replace(string(body), "\n", "", -1), nil
}

func (s *EC2Strategy) GetVaultToken(client *api.Client, role string) (string, error) {
	pkcs7, err := s.getPkcs7()
	if err != nil {
		return "", err
	}

	secret, err := client.Logical().Write("/auth/aws-ec2/login", map[string]interface{}{
		"role":  role,
		"pkcs7": pkcs7,
		"nonce": s.nonce,
	})
	if err != nil {
		return "", err
	}

	return secret.Auth.ClientToken, nil
}
