package main

import (
	"io/ioutil"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"git.yolt.io/infra/pkg.git/http/pinner"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

type vaultClient struct {
	clt          *api.Client
	tokenPath    string
	vpnCredsPath string
}

type credentials struct {
	IssuingCA   string
	PrivateKey  string
	Certificate string
}

func newVaultClient(vaultTokenPath, vaultVPNCredsPath string) (*vaultClient, error) {

	c := api.DefaultConfig()
	if c == nil {
		return nil, errors.New("could not create/read default configuration")
	}
	if c.Error != nil {
		return nil, errors.Wrapf(c.Error, "error encountered setting up default configuration")
	}

	// Force one TLS dialer for TLS and non-TLS endpoints.
	dialTLS := pinner.NewPinningDialer(pinnedPublicKeysPEM, allowedRootCertsPEM)

	c.HttpClient.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          10,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialTLS:               dialTLS,
		Dial:                  dialTLS,
	}

	clt, err := api.NewClient(c)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create vault client")
	}

	if vaultTokenPath == "" {
		home, _ := getHomeDir()
		vaultTokenPath = path.Join(home, ".vault-token")
	}

	vclt := &vaultClient{
		clt:          clt,
		tokenPath:    vaultTokenPath,
		vpnCredsPath: vaultVPNCredsPath,
	}

	err = vclt.updateToken()
	if err != nil {
		return nil, err
	}

	return vclt, nil
}

func (c *vaultClient) updateToken() error {

	token, err := ioutil.ReadFile(c.tokenPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read vault token path: %s", c.tokenPath)
	}

	c.clt.SetToken(strings.TrimSpace(string(token)))

	return nil
}

func (c *vaultClient) getVPNCredentials(email string) (*credentials, error) {
	data := map[string]interface{}{
		"common_name": email,
	}

	err := c.updateToken()
	if err != nil {
		return nil, err
	}

	secret, err := c.clt.Logical().Write(c.vpnCredsPath, data)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to write to vault-path %q", c.vpnCredsPath)
	}

	creds := &credentials{
		IssuingCA:   secret.Data["issuing_ca"].(string),
		PrivateKey:  secret.Data["private_key"].(string),
		Certificate: secret.Data["certificate"].(string),
	}

	return creds, nil
}
