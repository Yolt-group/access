package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/coreos/go-oidc"
)

type app struct {
	clientID       string
	clientSecret   string
	redirectURI    string
	vpnRemote      string
	debug          bool
	s3BucketName   string
	s3BucketRegion string
	s3KMSKeyID     string

	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider

	dexClient   *http.Client
	vaultClient *vaultClient
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	if a.debug {
		d, _ := httputil.DumpRequest(r, true)
		log.Printf("%s", d)
	}

	ctx := oidc.ClientContext(r.Context(), a.dexClient)
	oauth2Config := a.oauth2Config(nil)

	// Authorization redirect callback from OAuth2 auth flow.
	if errMsg := r.FormValue("error"); errMsg != "" {
		log.Printf("%s: %s", errMsg, r.FormValue("error_description"))
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		log.Printf("no code in request: %q", r.Form)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		log.Printf("cookie not found: %s", sessionCookieName)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	awsSession, err := newAWSSession(a.s3BucketRegion)
	if err != nil {
		log.Printf("failed to create AWS session: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sessionState, err := getState(awsSession, a.s3BucketName, cookie.Value)
	if err != nil {
		log.Printf("session state not found for session ID %q: %s", cookie.Value, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	err = deleteState(awsSession, a.s3BucketName, cookie.Value)
	if err != nil {
		log.Printf("failed to delete session state for session ID %q: %s", cookie.Value, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	state := r.FormValue("state")
	if state != sessionState {
		log.Printf("unexpected state: found %q, got %q", sessionState, state)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.Printf("failed to get token: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Print("no id_token in token response")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Printf("failed to verify ID token: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	_, ok = token.Extra("access_token").(string)
	if !ok {
		fmt.Print("no access_token in token response")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var claims claims
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("error getting claims from token: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	creds, err := a.vaultClient.getVPNCredentials(claims.Email)
	if err != nil {
		log.Printf("error getting VPN credentials from Vault: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/ovpn")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.ovpn\"", a.vpnRemote))

	renderOVPNConfig(w, *creds, a.vpnRemote)
}

func (a *app) handleDownload(w http.ResponseWriter, r *http.Request) {
	if a.debug {
		d, _ := httputil.DumpRequest(r, true)
		log.Printf("%s", d)
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		log.Printf("cookie not found: %s", sessionCookieName)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	state, err := randomString(stateLength)
	if err != nil {
		log.Print("failed to generate random string")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	awsSession, err := newAWSSession(a.s3BucketRegion)
	if err != nil {
		log.Printf("failed to create AWS session: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	err = putState(awsSession, a.s3KMSKeyID, a.s3BucketName, cookie.Value, state)
	if err != nil {
		log.Printf("failed to put state in S3: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	scopes := []string{"openid", "email", "groups"}
	authCodeURL := a.oauth2Config(scopes).AuthCodeURL(state)
	http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
}

func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {

	const index = `<!DOCTYPE html>
<html>
<head>
<style>
.center {
  display: flex;
  justify-content: center;
  align-items: center;
}
</style>
</head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<body>
  <form action="/download" method="get">
    <div class="center">
      <h1 style="font-size:4vw;">Download your OpenVPN configuration</h1>
    </div>
    <div class="center">
      <input type="submit" value="Download" style="font-size:2vw;">
    </div>
  </form>
</body>
</html>`

	sessionID, err := randomString(sessionIDLength)
	if err != nil {
		fmt.Print("failed to generate random string")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Set-Cookie", fmt.Sprintf("%s=%s", sessionCookieName, sessionID))
	w.Write([]byte(index))
}
