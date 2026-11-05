// Package paquet vérifie le manifeste signé d'un paquet de mise à jour —
// TO-DO 113.
//
// C'est le JUMEAU de vaultaire_serveur/core/paquetagent : le core écrit et
// signe, l'agent lit et vérifie. Les deux implémentations sont écrites à part,
// comme celles de la signature des politiques (gpo.CorpsSigne), et figées par
// le même vecteur de référence (vecteur_test.go, identique des deux côtés) :
// un octet de divergence ferait refuser tous les paquets du parc.
//
// Le format, ses raisons et ses refus sont décrits côté core ; ce paquet n'en
// garde que ce qui sert à VÉRIFIER. Le basculement (point 116, miseajour)
// l'appelle avant de toucher un seul fichier.
package paquet

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Domaine sépare les rôles de clés : `vaultaire-gpo-v1` pour les politiques.
// Une clé ne doit jamais pouvoir signer quelque chose qui passe pour le rôle de
// l'autre, même si les deux venaient à être confondues.
const Domaine = "vaultaire-pkg-v1"

// Fichiers est le jeu, dans l'ordre du manifeste.
var Fichiers = []string{
	"vaultaire_client",
	"pam_login_custom_module.so",
	"pam_logout_custom_module.so",
	"pam_ssh_auth_module.so",
	"libnss_vaultaire.so.2",
}

// PrefixePlateforme précède la famille dans le nom de plateforme.
const PrefixePlateforme = "linux-amd64-"

// Fichier est une ligne du manifeste.
type Fichier struct {
	Nom    string
	SHA256 string // 64 caractères hexadécimaux, minuscules
}

// Manifeste est le contenu signé.
type Manifeste struct {
	Version    string // trois nombres : 2.3.0
	Plateforme string // linux-amd64-<famille>
	Fichiers   []Fichier
}

var (
	formeVersion    = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)
	formePlateforme = regexp.MustCompile(`^linux-amd64-[a-z0-9]{1,32}$`)
	formeEmpreinte  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Valider vérifie qu'un manifeste peut s'écrire.
func (m Manifeste) Valider() error {
	if !formeVersion.MatchString(m.Version) {
		return fmt.Errorf("manifeste : version %q (trois nombres attendus)", m.Version)
	}
	if !formePlateforme.MatchString(m.Plateforme) {
		return fmt.Errorf("manifeste : plateforme %q (linux-amd64-<famille> attendu)", m.Plateforme)
	}
	if len(m.Fichiers) != len(Fichiers) {
		return fmt.Errorf("manifeste : %d fichier(s), %d attendus", len(m.Fichiers), len(Fichiers))
	}
	for i, f := range m.Fichiers {
		if f.Nom != Fichiers[i] {
			return fmt.Errorf("manifeste : ligne %d, %q au lieu de %q", i+4, f.Nom, Fichiers[i])
		}
		if !formeEmpreinte.MatchString(f.SHA256) {
			return fmt.Errorf("manifeste : empreinte de %s illisible", f.Nom)
		}
	}
	return nil
}

// Corps rend le texte canonique — ce qui est signé.
func (m Manifeste) Corps() (string, error) {
	if err := m.Valider(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(Domaine + "\n" + m.Version + "\n" + m.Plateforme + "\n")
	for _, f := range m.Fichiers {
		b.WriteString(f.Nom + " " + f.SHA256 + "\n")
	}
	return b.String(), nil
}

// Lire analyse un manifeste et refuse toute écriture non canonique.
func Lire(corps string) (Manifeste, error) {
	if !strings.HasSuffix(corps, "\n") {
		return Manifeste{}, fmt.Errorf("manifeste : fin de ligne finale manquante")
	}
	lignes := strings.Split(strings.TrimSuffix(corps, "\n"), "\n")
	if len(lignes) != 3+len(Fichiers) {
		return Manifeste{}, fmt.Errorf("manifeste : %d ligne(s), %d attendues", len(lignes), 3+len(Fichiers))
	}
	if lignes[0] != Domaine {
		return Manifeste{}, fmt.Errorf("manifeste : domaine %q, %q attendu", lignes[0], Domaine)
	}
	m := Manifeste{Version: lignes[1], Plateforme: lignes[2]}
	for _, l := range lignes[3:] {
		nom, somme, ok := strings.Cut(l, " ")
		if !ok {
			return Manifeste{}, fmt.Errorf("manifeste : ligne %q illisible", l)
		}
		m.Fichiers = append(m.Fichiers, Fichier{Nom: nom, SHA256: somme})
	}
	canon, err := m.Corps()
	if err != nil {
		return Manifeste{}, err
	}
	if canon != corps {
		return Manifeste{}, fmt.Errorf("manifeste : écriture non canonique")
	}
	return m, nil
}

// Famille rend la famille portée par la plateforme.
func (m Manifeste) Famille() string { return strings.TrimPrefix(m.Plateforme, PrefixePlateforme) }

// EmpreinteHex met une somme SHA-256 sous la forme du manifeste.
func EmpreinteHex(somme [32]byte) string { return hex.EncodeToString(somme[:]) }
