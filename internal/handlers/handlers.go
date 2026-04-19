package handlers

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"ice_gate_auth/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"encoding/json"
	"bytes"
)

type AuthHandler struct {
	Store    *store.Store
	WebAuthn *webauthn.WebAuthn
}

// normalizeBase64 handles both Standard and URL-Safe Base64
func normalizeBase64(input string) string {
	s := input
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	return s
}

// User represents a WebAuthn user
type User struct {
	id          []byte
	email       string
	displayName string
	credentials []webauthn.Credential
}

func (u *User) WebAuthnID() []byte { return u.id }
func (u *User) WebAuthnName() string { return u.email }
func (u *User) WebAuthnDisplayName() string { return u.displayName }
func (u *User) WebAuthnIcon() string { return "" }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// BeginRegistration starts the passkey creation flow
func (h *AuthHandler) BeginRegistration(c *gin.Context) {
	var body struct {
		Email  string `json:"email"`
		UserID string `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and user_id are required"})
		return
	}

	// Convert UUID string to raw bytes for standard WebAuthn compliance
	uid, err := uuid.Parse(body.UserID)
	if err != nil {
		fmt.Printf("❌ [WebAuthn] Invalid UserID format: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id format"})
		return
	}

	// Load existing credentials to prevent duplicate enrollment (excludeCredentials)
	creds, _ := h.Store.GetCredentialsByEmail(body.Email)
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
		id:          uid[:], // Raw 16 bytes
		email:       body.Email,
		displayName: body.Email,
		credentials: waCreds,
	}

	options, session, err := h.WebAuthn.BeginRegistration(user)
	if err != nil {
		fmt.Printf("❌ [WebAuthn] BeginRegistration Error for %s: %v\n", body.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "details": "Check if RPID or Origin matches configuration"})
		return
	}

	// Store FULL session in DB (contains challenge, userID, etc.)
	if err := h.Store.SaveSession(body.Email, session); err != nil {
		fmt.Printf("❌ [WebAuthn] SaveSession Error for %s: %v\n", body.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store session", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, options)
}

// FinishRegistration verifies the passkey creation
func (h *AuthHandler) FinishRegistration(c *gin.Context) {
	var body struct {
		Email  string `json:"email"`
		UserID string `json:"user_id"`
		Data   any    `json:"data"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	session, err := h.Store.GetSession(body.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session not found or expired"})
		return
	}

	// Reconstruct the user using the SAME UUID-based ID (raw 16 bytes)
	uid, _ := uuid.Parse(body.UserID)
	user := &User{id: uid[:], displayName: body.Email}

	// Use the library's manual parser since the data is nested
	dataJSON, err := json.Marshal(body.Data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to encode registration data"})
		return
	}

	// Create a mock request with the nested data body for the parser
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(dataJSON))
	req.Header.Set("Content-Type", "application/json")
	parsedResponse, err := protocol.ParseCredentialCreationResponse(req)
	if err != nil {
		fmt.Printf("❌ [WebAuthn] Parse Registration Error: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parse error for Registration", "details": err.Error()})
		return
	}

	credential, err := h.WebAuthn.CreateCredential(user, *session, parsedResponse)
	if err != nil {
		fmt.Printf("❌ [WebAuthn] Registration Verification Failed: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "verification failed",
			"details": err.Error(),
		})
		return
	}

	// Parse UserID
	parsedUserID, err := uuid.Parse(body.UserID)
	if err != nil {
		parsedUserID = uuid.New()
	}

	// Save the credential
	pubKey := base64.StdEncoding.EncodeToString(credential.PublicKey)
	credID := base64.StdEncoding.EncodeToString(credential.ID)
	
	if err := h.Store.SaveCredential(parsedUserID, body.Email, credID, pubKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save credential"})
		return
	}

	// Log the registration event
	h.Store.LogPasskeyEvent(body.Email, parsedUserID.String(), "registration", "Successful passkey enrollment")

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

	// 1. Get credentials
	creds, err := h.Store.GetCredentialsByEmail(body.Email)
	if err != nil || len(creds) == 0 {
		fmt.Printf("❌ [WebAuthn] No credentials found for %s\n", body.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no credentials found for user"})
		return
	}

	// 2. Map to WebAuthn credentials
	var waCreds []webauthn.Credential
	for _, sc := range creds {
		// Use a more robust decoding strategy
		id, err := base64.RawURLEncoding.DecodeString(normalizeBase64(sc.ID))
		if err != nil {
			id, _ = base64.StdEncoding.DecodeString(sc.ID)
		}
		
		key, err := base64.RawURLEncoding.DecodeString(normalizeBase64(sc.Key))
		if err != nil {
			key, _ = base64.StdEncoding.DecodeString(sc.Key)
		}

		waCreds = append(waCreds, webauthn.Credential{
			ID:        id,
			PublicKey: key,
		})
	}

	// Use raw binary comparison for ID search
	uid, err := uuid.Parse(creds[0].UserID)
	if err != nil {
		fmt.Printf("❌ [WebAuthn] Invalid UserID in DB for %s: %v\n", body.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database identity corruption"})
		return
	}

	user := &User{
		id:          uid[:],
		email:       body.Email,
		displayName: body.Email,
		credentials: waCreds,
	}

	options, session, err := h.WebAuthn.BeginLogin(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 3. Store FULL session in DB
	if err := h.Store.SaveSession(body.Email, session); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store session"})
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

	uid, err := uuid.Parse(creds[0].UserID)
	if err != nil {
		fmt.Printf("❌ [WebAuthn] Invalid UserID in DB for %s: %v\n", body.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database identity corruption"})
		return
	}

	user := &User{
		id:          uid[:],
		email:       body.Email,
		credentials: waCreds,
	}

	// Retrieve session from Store (using the new robust GetSession)
	session, err := h.Store.GetSession(body.Email)
	if err != nil {
		fmt.Printf("❌ [WebAuthn] Session expired or missing for %s\n", body.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "session expired or invalid"})
		return
	}

	// Use the library's manual parser since the data is nested
	dataJSON, err := json.Marshal(body.Data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to encode login data"})
		return
	}

	req, _ := http.NewRequest("POST", "/", bytes.NewReader(dataJSON))
	req.Header.Set("Content-Type", "application/json")
	parsedResponse, err := protocol.ParseCredentialRequestResponse(req)
	if err != nil {
		fmt.Printf("❌ [WebAuthn] Parse Login Error: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parse error for Login", "details": err.Error()})
		return
	}

	_, err = h.WebAuthn.ValidateLogin(user, *session, parsedResponse)
	if err != nil {
		fmt.Printf("❌ [WebAuthn] VALIDATION ATTEMPT 1 FAILED for %s: %v\n", body.Email, err)
		
		// IDENTITY ALIGNMENT STRATEGY (Rescue mission for mismatched encoding):
		// Some devices return the userHandle as a string (UUID or Base64) instead of binary.
		handleB := parsedResponse.Response.UserHandle
		
		if len(handleB) > 0 && !bytes.Equal(handleB, user.id) {
			handleStr := string(handleB)
			expectedIDHex := fmt.Sprintf("%x", user.id)
			
			fmt.Printf("   - 🔍 Investigating mismatch:\n")
			fmt.Printf("     - Expected ID (Hex):   %s\n", expectedIDHex)
			fmt.Printf("     - Received Handle (Hex): %x\n", handleB)
			fmt.Printf("     - Received Handle (Str): %s\n", handleStr)

			var alignedID []byte

			// Case 1: Handle is a String UUID (with-dashes)
			if u, err := uuid.Parse(handleStr); err == nil && bytes.Equal(u[:], user.id) {
				fmt.Printf("   - ℹ️ Alignment: Authenticator used String UUID.\n")
				alignedID = handleB
			} else {
				// Case 2: Handle is Base64 or Base64URL encoded version of our binary ID
				// Try various base64 variants
				variants := []func(string) ([]byte, error){
					func(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(normalizeBase64(s)) },
					func(s string) ([]byte, error) { return base64.URLEncoding.DecodeString(s) },
					func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) },
					func(s string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(normalizeBase64(s)) },
				}

				for i, decode := range variants {
					if decoded, err := decode(handleStr); err == nil && bytes.Equal(decoded, user.id) {
						fmt.Printf("   - ℹ️ Alignment: Authenticator used Base64 Variant %d.\n", i+1)
						alignedID = handleB
						break
					}
				}
			}

			if alignedID != nil {
				fmt.Printf("   - ✅ Alignment successful! Re-validating...\n")
				session.UserID = alignedID
				user.id = alignedID
				_, err = h.WebAuthn.ValidateLogin(user, *session, parsedResponse)
			}
		}

		if err != nil {
			fmt.Printf("❌ [WebAuthn] FINAL VALIDATION FAILED:\n")
			fmt.Printf("   - User ID (Hex):    %x\n", user.id)
			fmt.Printf("   - Session ID (Hex): %x\n", session.UserID)
			fmt.Printf("   - Handle ID (Hex):  %x\n", handleB)

			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "authentication failed",
				"message": err.Error(),
				"debug": gin.H{
					"user_id":    fmt.Sprintf("%x", user.id),
					"session_id": fmt.Sprintf("%x", session.UserID),
					"handle_id":  fmt.Sprintf("%x", handleB),
				},
			})
			return
		}
		fmt.Printf("   - ✅ [WebAuthn] Identity Alignment Permitted Successful Login!\n")
	}

	// 2. Clean up challenge and issue success
	h.Store.DeleteChallenge(body.Email)
	
	// Log the login event
	h.Store.LogPasskeyEvent(body.Email, creds[0].UserID, "login", "Successful passkey authentication")
	
	// Create a mock JWT for now (In real app, integrate with your auth system)
	token := fmt.Sprintf("passkey_jwt_%s", uuid.New().String())
	
	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"status": "success",
		"version": "1.0.2-uuid", // Updated to verify ID alignment deployment
		"user": gin.H{
			"email": body.Email,
		},
	})
}

// ServeAASA provides the Apple App Site Association file
func (h *AuthHandler) ServeAASA(c *gin.Context) {
	// Important: iOS requires the correct Content-Type 
	// Sending application/json specifically to resolve 1004 verification issues
	c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(`{"applinks":{"details":[{"appIDs":["JJ5CR7B87P.duylong.art.icegate"],"components":[{"/":"*"}]}]},"webcredentials":{"apps":["JJ5CR7B87P.duylong.art.icegate"]}}`))
}
