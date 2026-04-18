package webauthn

import (
	"os"

	"github.com/go-webauthn/webauthn/webauthn"
)

func NewWebAuthn() (*webauthn.WebAuthn, error) {
	rpID := os.Getenv("RP_ID")
	if rpID == "" {
		rpID = "passkey.duylong.art"
	}

	rpOrigin := os.Getenv("RP_ORIGIN")
	if rpOrigin == "" {
		rpOrigin = "https://" + rpID
	}

	wconfig := &webauthn.Config{
		RPDisplayName: "Ice Gate",
		RPID:          rpID,
		RPOrigins: []string{
			rpOrigin,
			"https://" + rpID,
			"ios:JJ5CR7B87P.duylong.art.icegate",
			"apple-app-site-association", // Some libraries use this as a placeholder
		},
	}

	return webauthn.New(wconfig)
}
