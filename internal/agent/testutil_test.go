package agent_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func mustFreePort(tb testing.TB) int {
	tb.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("get free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func generateTLSMaterial(tb testing.TB, dir string) (string, string, string, string, string) {
	tb.Helper()
	caCert, caKey := createCACert(tb)
	serverCert, serverKey := createSignedCert(tb, caCert, caKey, "127.0.0.1")
	clientCert, clientKey := createSignedCert(tb, caCert, caKey, "test-client")

	caCertPath := writePem(tb, dir, "ca-cert.pem", "CERTIFICATE", caCert.Raw)
	serverCertPath := writePem(tb, dir, "server-cert.pem", "CERTIFICATE", serverCert.Raw)
	serverKeyPath := writePem(tb, dir, "server-key.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))
	clientCertPath := writePem(tb, dir, "client-cert.pem", "CERTIFICATE", clientCert.Raw)
	clientKeyPath := writePem(tb, dir, "client-key.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))

	return caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath
}

func createCACert(tb testing.TB) (*x509.Certificate, *rsa.PrivateKey) {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generate ca key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: bigIntOne(tb),
		Subject: pkix.Name{
			CommonName:   "UT Test CA",
			Organization: []string{"UT"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse ca cert: %v", err)
	}
	return cert, key
}

func createSignedCert(tb testing.TB, caCert *x509.Certificate, caKey *rsa.PrivateKey, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: bigIntNow(tb),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"UT"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(12 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(cn); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		tb.Fatalf("create signed cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse cert: %v", err)
	}
	return cert, key
}

func writePem(tb testing.TB, dir, name, typ string, bytes []byte) string {
	tb.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		tb.Fatalf("create pem: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: bytes}); err != nil {
		tb.Fatalf("encode pem: %v", err)
	}
	return path
}

func bigIntOne(tb testing.TB) *big.Int {
	tb.Helper()
	return big.NewInt(1)
}

func bigIntNow(tb testing.TB) *big.Int {
	tb.Helper()
	return big.NewInt(time.Now().UnixNano())
}

func listenUDPOrSkip(tb testing.TB, addr *net.UDPAddr) *net.UDPConn {
	tb.Helper()
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		if isPermissionErr(err) {
			tb.Skipf("skipping: unable to bind UDP socket (%v)", err)
		}
		tb.Fatalf("listen udp failed: %v", err)
	}
	return conn
}

func isPermissionErr(err error) bool {
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.EPERM) {
			return true
		}
		if errors.Is(opErr.Err, os.ErrPermission) {
			return true
		}
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			if errors.Is(sysErr.Err, syscall.EPERM) {
				return true
			}
		}
	}
	return false
}
