package store

import (
	"context"
	"os"
	"time"

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
		ON CONFLICT DO NOTHING`
	
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

// GetCredentials retrieves all passkeys for an email
func (s *Store) GetCredentialsByEmail(email string) ([]struct{ ID, Key string }, error) {
	query := `
		SELECT credential_id, public_key FROM public.user_passkeys
		WHERE LOWER(email) = LOWER($1)`
	
	rows, err := s.Pool.Query(context.Background(), query, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []struct{ ID, Key string }
	for rows.Next() {
		var c struct{ ID, Key string }
		if err := rows.Scan(&c.ID, &c.Key); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, nil
}
