package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// Using the pooled connection string for better reliability
	connStr := "postgresql://postgres.wthislkepfufkbgiqegs:DuyLongPass%40200122@aws-1-ap-south-1.pooler.supabase.com:6543/postgres?sslmode=require&default_query_exec_mode=simple_protocol"

	fmt.Println("🔍 Attempting to connect to Supabase...")
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		log.Fatalf("❌ Failed to parse config: %v", err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		log.Fatalf("❌ Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Try a simple query
	var version string
	err = pool.QueryRow(context.Background(), "SELECT version()").Scan(&version)
	if err != nil {
		log.Fatalf("❌ Database connection failed: %v", err)
	}

	fmt.Printf("✅ SUCCESS! Connected to Supabase.\nServer version: %s\n", version)

	// Check if user_passkeys table has the email column
	var hasEmail bool
	checkQuery := `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns 
			WHERE table_name='user_passkeys' AND column_name='email'
		)`
	err = pool.QueryRow(context.Background(), checkQuery).Scan(&hasEmail)
	if err != nil {
		fmt.Printf("⚠️  Could not verify user_passkeys table: %v\n", err)
	} else if hasEmail {
		fmt.Println("✅ Verified: 'email' column exists in 'user_passkeys' table.")
	} else {
		fmt.Println("❌ CRITICAL: 'email' column is MISSING from 'user_passkeys' table!")
	}
}
