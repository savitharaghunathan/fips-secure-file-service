package client

import (
	"crypto/tls"
	"database/sql"
	"fmt"
)

// InsecureTLSConfig creates a TLS config that skips certificate verification.
// Violations:
//   - fips-go-tls-00100: InsecureSkipVerify disables certificate validation
func InsecureTLSConfig() *tls.Config {
	var cfg tls.Config
	cfg.InsecureSkipVerify = true
	return &cfg
}

// ConnectDB opens a PostgreSQL database connection with SSL disabled.
// Violations:
//   - fips-go-tls-00107: Database connection with TLS/SSL disabled
func ConnectDB() (*sql.DB, error) {
	connStr := "postgres://fileservice:password@db-host:5432/files?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("database connection failed: %w", err)
	}
	return db, nil
}
