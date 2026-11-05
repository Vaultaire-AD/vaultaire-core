package autoaddclientgo

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func cleHote(t *testing.T) ssh.Signer {
	t.Helper()
	_, prive, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(prive)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLaCleDHoteEstAppriseUneFoisPuisVerifiee(t *testing.T) {
	rep := t.TempDir()
	racine, err := os.OpenRoot(rep)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = racine.Close() }()
	fichier := filepath.Join(rep, NomClesConnues)
	cb := retenirCleHote(racine, NomClesConnues)
	a, b := cleHote(t).PublicKey(), cleHote(t).PublicKey()
	adr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 2222}

	if err := cb("192.0.2.1:2222", adr, a); err != nil {
		t.Fatal(err)
	}
	if err := cb("192.0.2.1:2222", adr, a); err != nil {
		t.Fatal(err)
	}
	contenu, _ := os.ReadFile(fichier)
	if n := strings.Count(string(contenu), "\n"); n != 1 {
		t.Fatalf("%d lignes après deux connexions avec la même clé : %q", n, contenu)
	}
	if !strings.HasPrefix(string(contenu), "[192.0.2.1]:2222 ssh-ed25519 ") {
		t.Fatalf("forme known_hosts attendue : %q", contenu)
	}
	// Clé changée : acceptée (comportement d'avant), inscrite, journalisée.
	if err := cb("192.0.2.1:2222", adr, b); err != nil {
		t.Fatal(err)
	}
	connues, err := clesConnues(racine, NomClesConnues, "[192.0.2.1]:2222", b.Type())
	if err != nil || len(connues) != 2 {
		t.Fatalf("clés connues : %d (%v)", len(connues), err)
	}
	if cleDHote("srv:22") != "srv" {
		t.Error("le port 22 ne s'écrit pas")
	}
}

// Un serveur SSH en mémoire, qui ne sert que le sous-système sftp.
func serveurSFTP(t *testing.T, racine string, cleClient ssh.PublicKey) string {
	t.Helper()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(cleClient.Marshal()) {
			return nil, nil
		}
		return nil, os.ErrPermission
	}}
	cfg.AddHostKey(cleHote(t))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, demandes, _ := nc.Accept()
					go func() {
						for d := range demandes {
							if d.Type == "subsystem" && len(d.Payload) > 4 &&
								string(d.Payload[4:4+binary.BigEndian.Uint32(d.Payload)]) == "sftp" {
								d.Reply(true, nil)
								srv, _ := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(racine))
								_ = srv.Serve()
								ch.Close()
								return
							}
							d.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()
	return l.Addr().String()
}

func TestLePaquetEstCopieAvecSesDroits(t *testing.T) {
	cle := cleHote(t)
	repCle := t.TempDir()
	pem, err := ssh.MarshalPrivateKey(cle, "")
	if err != nil {
		t.Skip("MarshalPrivateKey indisponible : ", err)
	}
	chemin := filepath.Join(repCle, "id")
	if err := os.WriteFile(chemin, pem.Bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = pem
	distant := t.TempDir()
	adr := serveurSFTP(t, distant, cle.PublicKey())
	h, p, _ := net.SplitHostPort(adr)
	port := 0
	for _, c := range p {
		port = port*10 + int(c-'0')
	}

	source := t.TempDir()
	os.MkdirAll(filepath.Join(source, "rocky"), 0o755)
	os.WriteFile(filepath.Join(source, "vaultaire_client"), []byte("bin"), 0o755)
	os.WriteFile(filepath.Join(source, "rocky", "pam.so"), []byte("so"), 0o644)

	client, err := connexionSSH("root", chemin, h, port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	cible := filepath.ToSlash(filepath.Join(distant, "opt", "vaultaire_client"))
	n, err := copierArborescence(sc, source, cible)
	if err != nil || n != 2 {
		t.Fatalf("%d fichier(s), %v", n, err)
	}
	info, err := os.Stat(filepath.Join(distant, "opt", "vaultaire_client", "vaultaire_client"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("binaire copié sans son bit d'exécution : %v %v", info, err)
	}
	if b, _ := os.ReadFile(filepath.Join(distant, "opt", "vaultaire_client", "rocky", "pam.so")); string(b) != "so" {
		t.Fatal("sous-répertoire non copié")
	}
	if _, err := os.Stat(filepath.Join(repCle, "known_hosts")); err != nil {
		t.Fatal("la clé d'hôte n'a pas été inscrite à côté de la clé de connexion")
	}
}
