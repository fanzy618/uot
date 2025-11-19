package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/fanzy618/uot/internal/config"
)

// ClientConfig builds a *tls.Config for the client role.
func ClientConfig(cfg config.TLSConfig, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}

	pool, err := loadCAPool(cfg.CACert)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pool,
		ServerName:   serverName,
	}, nil
}

// ServerConfig builds a *tls.Config for the server role enforcing mTLS.
func ServerConfig(cfg config.TLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	pool, err := loadCAPool(cfg.CACert)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("add ca cert: no certs found in %s", path)
	}
	return pool, nil
}
