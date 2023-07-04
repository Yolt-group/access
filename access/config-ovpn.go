package main

import (
	"log"
	"net/http"
	"text/template"
)

func renderOVPNConfig(w http.ResponseWriter, creds credentials, remote string) {

	config := template.Must(template.New(remote + ".ovpn").Parse(`
client
dev tun
proto tcp
nobind
remote {{.Remote}} 1194
remote-random
resolv-retry 10
verify-x509-name "O=Yolt, OU=SRE, CN={{.Remote}}"
cipher AES-256-GCM
tun-mtu 1500
auth-nocache
connect-timeout 5

remote-cert-tls server

<ca>
{{.IssuingCA}}
</ca>

<cert>
{{.Certificate}}
</cert>

<key>
{{.PrivateKey}}
</key>
`))

	data := struct {
		credentials
		Remote string
	}{
		credentials: creds,
		Remote:      remote,
	}

	err := config.Execute(w, data)
	if err != nil {
		log.Printf("Error rendering %q: %s", config.Name(), err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
