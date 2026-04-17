package handlers

import (
	"encoding/base64"
	"net/http"

	"ice_gate_auth/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type AuthHandler struct {
	Store    *store.Store
	WebAuthn *webauthn.WebAuthn
}

// User represents a WebAuthn user
type User struct {
	id          []byte
	displayName string
	credentials []webauthn.Credential
}

func (u *User) WebAuthnID() []byte { return u.id }
func (u *User) WebAuthnName() string { return u.displayName }
func (u *User) WebAuthnDisplayName() string { return u.displayName }
func (u *User) WebAuthnIcon() string { return "" }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// BeginRegistration starts the passkey creation flow
func (h *AuthHandler) BeginRegistration(c *gin.Context) {
	var body struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is required"})
		return
	}

	user := &User{
		id:          uuid.New().NodeID(), // Temporary ID for registration
		displayName: body.Email,
	}

	options, session, err := h.WebAuthn.BeginRegistration(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Store challenge in DB
	if err := h.Store.SaveChallenge(body.Email, session.Challenge); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store challenge"})
		return
	}

	c.JSON(http.StatusOK, options)
}

// FinishRegistration verifies the passkey creation
func (h *AuthHandler) FinishRegistration(c *gin.Context) {
	var body struct {
		Email string `json:"email"`
		Data  any    `json:"data"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	challenge, err := h.Store.GetChallenge(body.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "challenge not found or expired"})
		return
	}

	// Reconstruct the user (simplified for this logic)
	user := &User{id: []byte(body.Email), displayName: body.Email}
	session := webauthn.SessionData{Challenge: challenge}

	credential, err := h.WebAuthn.FinishRegistration(user, session, c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "verification failed", "details": err.Error()})
		return
	}

	// Save the credential
	pubKey := base64.StdEncoding.EncodeToString(credential.PublicKey)
	credID := base64.StdEncoding.EncodeToString(credential.ID)
	
	if err := h.Store.SaveCredential(uuid.New(), body.Email, credID, pubKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save credential"})
		return
	}

	h.Store.DeleteChallenge(body.Email)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// ServeAASA provides the Apple App Site Association file
func (h *AuthHandler) ServeAASA(c *gin.Context) {
	aasa := gin.H{
		"webcredentials": gin.H{
			"apps": []string{"JJ5CR7B87P.duylong.art.icegate"},
		},
	}
	// Important: iOS requires the correct Content-Type without extension
	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, aasa)
}
