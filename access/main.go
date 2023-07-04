package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

type claims struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

const (
	sessionIDLength   = 32
	stateLength       = 32
	sessionCookieName = "session-id"
)

func run() error {

	clientID := flag.String("client-id", "access", "OAuth2 client ID of this application.")
	clientSecret := flag.String("client-secret", "...", "OAuth2 client secret of this application.")
	redirectURL := flag.String("redirect-uri", "http://127.0.0.1:5555/callback", "Callback URL for OAuth2 responses.")
	issuerURL := flag.String("issuer", "http://127.0.0.1:5556/dex", "URL of the OpenID Connect issuer.")
	listen := flag.String("listen", "http://127.0.0.1:5555", "HTTP(S) address to listen at.")
	tlsCert := flag.String("tls-cert", "/vault/secrets/cert", "X509 cert file to present when serving HTTPS.")
	tlsKey := flag.String("tls-key", "/vault/secrets/private-key", "Private key for the HTTPS cert.")
	rootCAs := flag.String("issuer-root-ca", "", "Root certificate authorities for the issuer. Defaults to host certs.")
	vaultTokenPath := flag.String("vault-token-path", "/vault/secrets/token", "Vault token path.")
	vaultVPNCredsPath := flag.String("vault-vpn-creds-path", "management-dta/newvpn/issue/clt", "Vault path for VPN client credentials.")
	s3BucketName := flag.String("s3-bucket-name", "yolt-management-dta-access", "S3 bucket name for state storage.")
	s3BucketRegion := flag.String("s3-bucket-region", "eu-central-1", "S3 bucket region for state storage.")
	s3KMSKeyID := flag.String("s3-kms-key-id", "arn:aws:kms:eu-central-1:562962985364:key/536a9cbf-2211-4dac-854f-da377b0fba86", "S3 KMS key ID.")
	vpnRemote := flag.String("vpn-remote", "vpn.management-dta.yolt.io", "VPN remote for OpenVPN config.")
	debug := flag.Bool("debug", false, "Print all request and responses from the OpenID Connect issuer.")

	flag.Parse()

	a := app{
		redirectURI:    *redirectURL,
		clientSecret:   *clientSecret,
		clientID:       *clientID,
		vpnRemote:      *vpnRemote,
		debug:          *debug,
		s3BucketName:   *s3BucketName,
		s3BucketRegion: *s3BucketRegion,
		s3KMSKeyID:     *s3KMSKeyID,
	}

	vclt, err := newVaultClient(*vaultTokenPath, *vaultVPNCredsPath)
	if err != nil {
		return errors.Wrapf(err, "failed to create vault client")
	}
	a.vaultClient = vclt

	u, err := url.Parse(a.redirectURI)
	if err != nil {
		return errors.Wrapf(err, "parse redirect-uri")
	}
	listenURL, err := url.Parse(*listen)
	if err != nil {
		return errors.Wrapf(err, "parse listen address")
	}

	if *rootCAs != "" {
		client, err := httpClientForRootCAs(*rootCAs)
		if err != nil {
			return err
		}
		a.dexClient = client
	}

	if *debug {
		if a.dexClient == nil {
			a.dexClient = &http.Client{
				Transport: debugTransport{http.DefaultTransport},
			}
		} else {
			a.dexClient.Transport = debugTransport{a.dexClient.Transport}
		}
	}

	if a.dexClient == nil {
		a.dexClient = http.DefaultClient
	}

	ctx := oidc.ClientContext(context.Background(), a.dexClient)
	provider, err := oidc.NewProvider(ctx, *issuerURL)
	if err != nil {
		return errors.Wrapf(err, "failed to query provider %q", *issuerURL)
	}

	a.provider = provider
	a.verifier = provider.Verifier(&oidc.Config{ClientID: a.clientID})

	r := mux.NewRouter()
	r.HandleFunc("/", a.handleIndex).Methods("GET")
	r.HandleFunc("/download", a.handleDownload).Methods("GET")
	r.HandleFunc(u.Path, a.handleCallback).Methods("GET")

	log.Printf("listening on %s", *listen)
	switch listenURL.Scheme {
	case "http":
		return http.ListenAndServe(listenURL.Host, secureHandler(r))
	case "https":
		return http.ListenAndServeTLS(listenURL.Host, *tlsCert, *tlsKey, secureHandler(r))
	default:
		return fmt.Errorf("listen address %q is not using http or https", *listen)
	}
}

func main() {

	err := run()
	if err != nil {
		fmt.Printf("failed to run: %s", err)
	}
}
