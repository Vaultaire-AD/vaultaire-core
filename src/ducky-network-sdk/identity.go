package duckynetwork

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Identity est ce qu'un client service possède après son enrôlement.
//
// # Pourquoi elle est persistée séparément de la configuration
//
// La configuration est écrite par un humain ou un outil de déploiement ; elle
// contient la clé d'enrôlement et l'adresse du core. L'identité, elle, est
// produite par le programme lui-même et ne doit jamais être éditée à la main.
//
// Les séparer permet de la détruire seule lors d'une auto-réinitialisation, sans
// toucher à ce que l'administrateur a écrit — et sans lui redemander une clé
// d'enrôlement qu'il a déjà fournie.
type Identity struct {
	ComputeurID string `json:"computeur_id"`
	ClientType  string `json:"client_type"`
	PrivateKey  string `json:"private_key_pem"`
	PublicKey   string `json:"public_key_pem"`
	EnrolledAt  string `json:"enrolled_at"`
}

// Valid indique si l'identité est exploitable.
func (i Identity) Valid() bool {
	return strings.TrimSpace(i.ComputeurID) != "" && strings.TrimSpace(i.PrivateKey) != ""
}

// LoadIdentity lit l'identité depuis le disque.
//
// Une absence de fichier n'est PAS une erreur : c'est l'état normal avant le
// premier enrôlement. L'appelant distingue les deux par Valid().
func LoadIdentity(path string) (Identity, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Identity{}, nil
	}
	if err != nil {
		return Identity{}, fmt.Errorf("lecture de l'identité : %w", err)
	}
	var id Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		// Un fichier illisible est traité comme une absence d'identité plutôt
		// que comme une panne : le programme se réenrôlera, ce qui est
		// exactement ce qu'on veut d'un fichier corrompu.
		return Identity{}, nil
	}
	return id, nil
}

// SaveIdentity écrit l'identité, en 0600.
//
// L'écriture passe par un fichier temporaire renommé : une coupure de courant au
// mauvais moment laisserait sinon un fichier tronqué, donc une clé privée
// inutilisable et un service qui ne peut plus se connecter ni prouver qui il est.
func SaveIdentity(path string, id Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("création du dossier d'identité : %w", err)
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("sérialisation de l'identité : %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("écriture de l'identité : %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("remplacement de l'identité : %w", err)
	}
	return nil
}

// ResetIdentity efface l'identité pour forcer un réenrôlement.
//
// Utilisée quand le core n'accepte plus notre clé : le client a été supprimé
// côté serveur, ou sa clé publique remplacée. Continuer à réessayer avec une
// identité que plus personne ne reconnaît ne mène nulle part ; il faut repartir
// d'une paire neuve.
func ResetIdentity(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("suppression de l'identité : %w", err)
	}
	return nil
}
