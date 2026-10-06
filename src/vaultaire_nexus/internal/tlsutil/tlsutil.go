// Package tlsutil fournit le certificat du service.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/store"
)

// Load rend la configuration TLS : fichiers fournis, ou certificat auto-signé
// créé au premier démarrage dans <data_dir>/tls/ et réutilisé ensuite.
//
// Le certificat auto-signé couvre le nom de la machine, ses adresses, et les
// noms déclarés dans tls.dns_names. Docker exige qu'il soit déposé dans
// /etc/docker/certs.d/<hôte>:<port>/ca.crt sur chaque client.
func Load(cfg config.Config) (*tls.Config, string, error) {
	certFile, keyFile := cfg.TLS.CertFile, cfg.TLS.KeyFile
	created := ""
	if certFile == "" && cfg.TLS.SelfSigned {
		dir := filepath.Join(cfg.DataDir, "tls")
		certFile, keyFile = filepath.Join(dir, "nexus.crt"), filepath.Join(dir, "nexus.key")
		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			if err := generate(certFile, keyFile, cfg.TLS.DNSNames, cfg.TLS.IPs); err != nil {
				return nil, "", fmt.Errorf("certificat auto-signé : %w", err)
			}
			created = certFile
		}
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, "", err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, created, nil
}

func generate(certFile, keyFile string, names, ips []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	dns := append([]string{"localhost"}, names...)
	if host != "" {
		dns = append(dns, host)
	}
	var addrs []net.IP
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil {
			addrs = append(addrs, ip)
		}
	}
	addrs = append(addrs, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	if ifaces, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifaces {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
				addrs = append(addrs, n.IP)
			}
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: firstOr(names, host, "vaultaire-nexus"), Organization: []string{"Vaultaire Nexus"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(3, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Marqué CA : c'est ce qui permet de le déposer tel quel comme ancre de
		// confiance (docker certs.d, update-ca-trust).
		IsCA: true, BasicConstraintsValid: true,
		DNSNames: dns, IPAddresses: addrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := store.WriteFileAtomic(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return store.WriteFileAtomic(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func firstOr(l []string, v ...string) string {
	if len(l) > 0 {
		return l[0]
	}
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
