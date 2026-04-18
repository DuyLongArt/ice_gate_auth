package store

import (
	"context"
	"os"
	"time"
	"encoding/json"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	Pool *pgxpool.Pool
}

func NewStore() (*Store, error) {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		// Using the pooler URL with correct password encoding for 'DuyLongPass@200122'
		connStr = "postgresql://postgres.wthislkepfufkbgiqegs:DuyLongPass%40200122@aws-1-ap-south-1.pooler.supabase.com:6543/postgres?sslmode=require&default_query_exec_mode=simple_protocol"
	}

	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, err
	}

	return &Store{Pool: pool}, nil
}

// SaveChallenge stores a new WebAuthn challenge for an email
func (s *Store) SaveChallenge(email, challenge string) error {
	query := `
		INSERT INTO public.webauthn_challenges (challenge, email, expires_at)
		VALUES ($1, LOWER($2), $3)
		ON CONFLICT (email) DO UPDATE SET 
			challenge = EXCLUDED.challenge, 
			expires_at = EXCLUDED.expires_at,
			created_at = NOW()`
	
	expiresAt := time.Now().Add(5 * time.Minute)
	_, err := s.Pool.Exec(context.Background(), query, challenge, email, expiresAt)
	return err
}

// GetChallenge retrieves the most recent valid challenge for an email
func (s *Store) GetChallenge(email string) (string, error) {
	var challenge string
	query := `
		SELECT challenge FROM public.webauthn_challenges
		WHERE LOWER(email) = LOWER($1) AND expires_at > $2
		ORDER BY created_at DESC LIMIT 1`
	
	err := s.Pool.QueryRow(context.Background(), query, email, time.Now()).Scan(&challenge)
	return challenge, err
}

// DeleteChallenge removes challenges for an email after use
func (s *Store) DeleteChallenge(email string) error {
	query := `DELETE FROM public.webauthn_challenges WHERE LOWER(email) = LOWER($1)`
	_, err := s.Pool.Exec(context.Background(), query, email)
	return err
}

// SaveCredential stores a new passkey credential
func (s *Store) SaveCredential(userID uuid.UUID, email, credentialID, publicKey string) error {
	query := `
		INSERT INTO public.user_passkeys (user_id, email, credential_id, public_key)
		VALUES ($1, LOWER($2), $3, $4)`
	
	_, err := s.Pool.Exec(context.Background(), query, userID, email, credentialID, publicKey)
	return err
}

// GetCredentials retrieves all passkeys for an email along with the UserID
func (s *Store) GetCredentialsByEmail(email string) ([]struct{ ID, Key, UserID string }, error) {
	query := `
		SELECT credential_id, public_key, user_id FROM public.user_passkeys
		WHERE LOWER(email) = LOWER($1)
		ORDER BY created_at DESC`
	
	rows, err := s.Pool.Query(context.Background(), query, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []struct{ ID, Key, UserID string }
	for rows.Next() {
		var c struct{ ID, Key, UserID string }
		if err := rows.Scan(&c.ID, &c.Key, &c.UserID); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, nil
}

// LogPasskeyEvent records an authentication event in the database
func (s *Store) LogPasskeyEvent(email, personID, eventType, metadata string) error {
	query := `
		INSERT INTO public.auth_logs (email, person_id, event_type, metadata)
		VALUES (LOWER($1), $2, $3, $4)`
	
	_, err := s.Pool.Exec(context.Background(), query, email, personID, eventType, metadata)
	return err
}

// SaveSession stores the WebAuthn session data as JSON
func (s *Store) SaveSession(email string, session *webauthn.SessionData) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	
	query := `
		INSERT INTO public.webauthn_challenges (email, challenge, session_data, expires_at)
		VALUES (LOWER($1), $2, $3, $4)
		ON CONFLICT (email) DO UPDATE SET 
			challenge = EXCLUDED.challenge,
			session_data = EXCLUDED.session_data,
			expires_at = EXCLUDED.expires_at,
			created_at = NOW()`
	
	expiresAt := time.Now().Add(10 * time.Minute)
	_, err = s.Pool.Exec(context.Background(), query, email, session.Challenge, data, expiresAt)
	return err
}

// GetSession retrieves and deserializes the WebAuthn session data
func (s *Store) GetSession(email string) (*webauthn.SessionData, error) {
	var data []byte
	query := `
		SELECT session_data FROM public.webauthn_challenges
		WHERE LOWER(email) = LOWER($1) AND expires_at > $2
		ORDER BY created_at DESC LIMIT 1`
	
	err := s.Pool.QueryRow(context.Background(), query, email, time.Now()).Scan(&data)
	if err != nil {
		return nil, err
	}
	
	var session webauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	return &session, nil
}
