package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "postgresql://postgres.wthislkepfufkbgiqegs:DuyLongPass%40200122@aws-1-ap-south-1.pooler.supabase.com:6543/postgres?sslmode=require&default_query_exec_mode=simple_protocol"
	}

	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	rows, err := pool.Query(context.Background(), "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'webauthn_challenges' AND table_schema = 'public'")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	fmt.Println("Columns in webauthn_challenges:")
	for rows.Next() {
		var n, t string
		rows.Scan(&n, &t)
		fmt.Printf("- %s: %s\n", n, t)
	}
}
