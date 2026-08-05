// Package keymanagement range et relit les clés sur le disque.
//
// # Où vivent les clés
//
// Trois fichiers, dans un dossier que le programme hôte choisit :
//
//	private_key.pem    notre clé privée — ne quitte JAMAIS cet hôte
//	public_key.pem     notre clé publique, telle qu'envoyée au core
//	server_public.pem  la clé publique du core, obtenue par « askkey »
//
// L'identité (identifiant machine, type) vit à côté, dans identity.json.
package keymanagement

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Store est le dossier où le programme range ses clés.
type Store struct{ Dir string }

// NewStore prépare le dossier, en 0700.
func NewStore(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("dossier de clés non renseigné")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("création de %s : %w", dir, err)
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.Dir, name) }

// Noms de fichiers, pour que le programme hôte puisse les documenter.
const (
	PrivateKeyFile   = "private_key.pem"
	PublicKeyFile    = "public_key.pem"
	ServerKeyFile    = "server_public.pem"
	IdentityFile     = "identity.json"
	tempSuffix       = ".tmp"
	privateKeyMode   = 0o600
	publicKeyMode    = 0o644
	identityFileMode = 0o600
)

// Identity est ce qu'un client possède après enrôlement.
type Identity struct {
	ComputeurID string `json:"computeur_id"`
	ClientType  string `json:"client_type"`
	EnrolledAt  string `json:"enrolled_at"`
}

// Valid indique si l'identité est exploitable.
func (i Identity) Valid() bool { return strings.TrimSpace(i.ComputeurID) != "" }

// GetClientPrivateKey lit notre clé privée.
func (s *Store) GetClientPrivateKey() (string, error) { return s.read(PrivateKeyFile) }

// GetClientPublicKey lit notre clé publique.
func (s *Store) GetClientPublicKey() (string, error) { return s.read(PublicKeyFile) }

// GetServeurPublicKey lit la clé publique du core.
func (s *Store) GetServeurPublicKey() (string, error) { return s.read(ServerKeyFile) }

// HasServeurPublicKey indique s'il faut lancer un « askkey ».
func (s *Store) HasServeurPublicKey() bool {
	content, err := s.read(ServerKeyFile)
	return err == nil && strings.Contains(content, "-----BEGIN")
}

// HasClientKeys indique si une paire locale existe déjà.
func (s *Store) HasClientKeys() bool {
	content, err := s.read(PrivateKeyFile)
	return err == nil && strings.Contains(content, "-----BEGIN")
}

// WriteServeurPublicKey enregistre la clé reçue par « askkey ».
func (s *Store) WriteServeurPublicKey(pem string) error {
	return s.write(ServerKeyFile, pem, publicKeyMode)
}

// WriteClientKeys enregistre la paire produite à l'enrôlement.
func (s *Store) WriteClientKeys(privatePEM, publicPEM string) error {
	if err := s.write(PrivateKeyFile, privatePEM, privateKeyMode); err != nil {
		return err
	}
	return s.write(PublicKeyFile, publicPEM, publicKeyMode)
}

// LoadIdentity lit l'identité.
//
// Une absence de fichier n'est PAS une erreur : c'est l'état normal avant le
// premier enrôlement. L'appelant distingue les deux par Valid().
func (s *Store) LoadIdentity() (Identity, error) {
	raw, err := os.ReadFile(s.path(IdentityFile))
	if os.IsNotExist(err) {
		return Identity{}, nil
	}
	if err != nil {
		return Identity{}, fmt.Errorf("lecture de l'identité : %w", err)
	}
	var id Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		// Un fichier corrompu est traité comme une absence : le programme se
		// réenrôlera, ce qui est exactement ce qu'on veut d'un fichier illisible.
		return Identity{}, nil
	}
	return id, nil
}

// SaveIdentity écrit l'identité.
func (s *Store) SaveIdentity(id Identity) error {
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("sérialisation de l'identité : %w", err)
	}
	return s.write(IdentityFile, string(data), identityFileMode)
}

// Reset efface identité ET paire locale, pour forcer un réenrôlement complet.
//
// Les deux ensemble : garder la paire en effaçant l'identité laisserait le
// programme se réenrôler avec une clé publique que le core connaît peut-être
// déjà sous un autre identifiant.
func (s *Store) Reset() error {
	for _, name := range []string{IdentityFile, PrivateKeyFile, PublicKeyFile} {
		if err := os.Remove(s.path(name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("suppression de %s : %w", name, err)
		}
	}
	return nil
}

func (s *Store) read(name string) (string, error) {
	raw, err := os.ReadFile(s.path(name))
	if err != nil {
		return "", fmt.Errorf("lecture de %s : %w", name, err)
	}
	return string(raw), nil
}

// write passe par un fichier temporaire renommé.
//
// Une coupure au mauvais moment laisserait sinon une clé privée tronquée : le
// programme ne pourrait plus ni se connecter ni prouver qui il est, et le
// diagnostic serait bien plus long qu'un fichier simplement absent.
func (s *Store) write(name, content string, mode os.FileMode) error {
	tmp := s.path(name + tempSuffix)
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return fmt.Errorf("écriture de %s : %w", name, err)
	}
	if err := os.Rename(tmp, s.path(name)); err != nil {
		return fmt.Errorf("remplacement de %s : %w", name, err)
	}
	return nil
}
