package handlers

import (
	"encoding/base64"
	"fmt"
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
// BeginLogin starts the passkey login flow
func (h *AuthHandler) BeginLogin(c *gin.Context) {
	var body struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is required"})
		return
	}

	// 1. Fetch user credentials from DB
	creds, err := h.Store.GetCredentialsByEmail(body.Email)
	if err != nil || len(creds) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found or no passkeys registered"})
		return
	}

	// 2. Map to WebAuthn credentials
	var waCreds []webauthn.Credential
	for _, sc := range creds {
		id, _ := base64.StdEncoding.DecodeString(sc.ID)
		key, _ := base64.StdEncoding.DecodeString(sc.Key)
		waCreds = append(waCreds, webauthn.Credential{
			ID:        id,
			PublicKey: key,
		})
	}

	user := &User{
		id:          []byte(body.Email),
		displayName: body.Email,
		credentials: waCreds,
	}

	options, session, err := h.WebAuthn.BeginLogin(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 3. Store challenge in DB
	if err := h.Store.SaveChallenge(body.Email, session.Challenge); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store challenge"})
		return
	}

	c.JSON(http.StatusOK, options)
}

// FinishLogin verifies the passkey login assertion
func (h *AuthHandler) FinishLogin(c *gin.Context) {
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

	// 1. Fetch user credentials again for verification
	creds, err := h.Store.GetCredentialsByEmail(body.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user credentials"})
		return
	}

	var waCreds []webauthn.Credential
	for _, sc := range creds {
		id, _ := base64.StdEncoding.DecodeString(sc.ID)
		key, _ := base64.StdEncoding.DecodeString(sc.Key)
		waCreds = append(waCreds, webauthn.Credential{
			ID:        id,
			PublicKey: key,
		})
	}

	user := &User{
		id:          []byte(body.Email),
		displayName: body.Email,
		credentials: waCreds,
	}

	session := webauthn.SessionData{Challenge: challenge}

	_, err = h.WebAuthn.FinishLogin(user, session, c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed", "details": err.Error()})
		return
	}

	// 2. Clean up challenge and issue success
	h.Store.DeleteChallenge(body.Email)
	
	// Create a mock JWT for now (In real app, integrate with your auth system)
	token := fmt.Sprintf("passkey_jwt_%s", uuid.New().String())
	
	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"status": "success",
		"version": "1.0.1-aligned", // Added for deployment verification
		"user": gin.H{
			"email": body.Email,
		},
	})
}

// ServeAASA provides the Apple App Site Association file
func (h *AuthHandler) ServeAASA(c *gin.Context) {
	// Important: iOS requires the correct Content-Type 
	// Sending application/json specifically to resolve 1004 verification issues
	c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(fmt.Sprintf(`{"applinks":{"details":[{"appIDs":["JJ5CR7B87P.duylong.art.icegate"],"components":[{"/":"*"}]}]},"webcredentials":{"apps":["JJ5CR7B87P.duylong.art.icegate"]}}`)))
}
