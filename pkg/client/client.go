package client

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net/http"
)

// FileServiceClient connects to remote file storage and database services.
type FileServiceClient struct {
	httpClient *http.Client
}

// NewInsecureClient creates an HTTP client that skips TLS certificate verification.
// Violations:
//   - fips-go-tls-00100: InsecureSkipVerify disables certificate validation
func NewInsecureClient() *FileServiceClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &FileServiceClient{
		httpClient: &http.Client{
			Transport: transport,
		},
	}
}

// UploadFile uploads an encrypted file to the remote storage service.
func (c *FileServiceClient) UploadFile(url string, data []byte) error {
	resp, err := c.httpClient.Post(url, "application/octet-stream", nil)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload returned status %d", resp.StatusCode)
	}
	return nil
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
