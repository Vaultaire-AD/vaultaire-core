package compte

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Le mot de passe du compte local — TO-DO 195.
//
// # Ce qui n'allait pas
//
// Jusqu'au 195, le compte local portait le mot de passe du DOMAINE. Après une
// première connexion par Vaultaire, Windows propose la tuile de ce compte avec
// son propre fournisseur mot de passe — à l'ouverture comme au déverrouillage —
// et le vérifie seul, contre le compte local : ni le core, ni le code TOTP. Le
// second facteur était contourné par la tuile d'à côté.
//
// # Ce qui est fait
//
// Le compte local porte un mot de passe ALÉATOIRE, que personne ne tape et que
// l'utilisateur ne connaît pas. L'agent le garde, chiffré pour la machine
// (DPAPI), et le rend à la tuile Vaultaire après l'accord du core : c'est lui
// que la tuile met dans le bloc d'ouverture de session. La tuile du compte
// local de Windows demande donc un mot de passe que personne n'a.
//
// Pourquoi pas un filtre (ICredentialProviderFilter) : il retire un
// fournisseur entier, pas des comptes. Filtrer celui de Microsoft fermerait le
// poste aux comptes locaux d'administration — l'issue de secours.
//
// # Il ne change pas à chaque connexion
//
// Windows protège les secrets d'un compte local (DPAPI : mots de passe
// enregistrés des navigateurs, gestionnaire d'identifiants) par son mot de
// passe. Une REMISE à zéro par l'agent les rend illisibles. Le mot de passe est
// donc tiré une fois, gardé, et reposé seulement s'il ne marche plus — compte
// recréé, ou mot de passe changé hors de Vaultaire.

// LongueurMotDePasseLocal : de quoi satisfaire toute politique de longueur, et
// rendre la force brute sans objet.
const LongueurMotDePasseLocal = 32

// Quatre familles : toute exigence de complexité de Windows est satisfaite
// (trois familles sur quatre suffisent). Pas de guillemet ni de barre oblique
// inverse : le secret traverse du JSON et des journaux de débogage d'outils
// tiers, autant ne rien leur donner à échapper.
const (
	familleMajuscules = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	familleMinuscules = "abcdefghijkmnopqrstuvwxyz"
	familleChiffres   = "23456789"
	familleSymboles   = "-_.!#%+=@:"
	alphabetLocal     = familleMajuscules + familleMinuscules + familleChiffres + familleSymboles
)

// GenererMotDePasseLocal tire un mot de passe aléatoire, les quatre familles
// présentes.
func GenererMotDePasseLocal() (string, error) {
	borne := big.NewInt(int64(len(alphabetLocal)))
	for essai := 0; essai < 100; essai++ {
		var b strings.Builder
		for i := 0; i < LongueurMotDePasseLocal; i++ {
			n, err := rand.Int(rand.Reader, borne)
			if err != nil {
				return "", fmt.Errorf("tirage du mot de passe local : %w", err)
			}
			b.WriteByte(alphabetLocal[n.Int64()])
		}
		if s := b.String(); motDePasseComplet(s) {
			return s, nil
		}
	}
	return "", errors.New("tirage du mot de passe local : aucune des 100 tentatives n'a les quatre familles")
}

func motDePasseComplet(s string) bool {
	for _, famille := range []string{familleMajuscules, familleMinuscules, familleChiffres, familleSymboles} {
		if !strings.ContainsAny(s, famille) {
			return false
		}
	}
	return true
}

// --- garde du secret ------------------------------------------------------------

// DossierSecrets : où l'agent garde le mot de passe de chaque compte local.
// Sous la racine de l'agent, dont install.ps1 réserve l'accès à SYSTEM et aux
// administrateurs ; chaque fichier est EN PLUS chiffré par DPAPI pour la
// machine — une copie du disque ne les livre pas.
var DossierSecrets = `C:\ProgramData\Vaultaire\comptes`

// proteger / deproteger : DPAPI sous Windows (secret_windows.go). Variables,
// pour éprouver la garde sous Linux.
var (
	proteger   func([]byte) ([]byte, error)
	deproteger func([]byte) ([]byte, error)
)

// nomDeFichierSur : le nom local sert de nom de fichier. Il sort de NomLocal,
// mais rien ne coûte de le revérifier avant de composer un chemin.
var nomDeFichierSur = regexp.MustCompile(`^[a-z0-9._-]{1,20}$`)

func cheminSecret(nom string) (string, error) {
	if !nomDeFichierSur.MatchString(nom) || strings.Trim(nom, ".") == "" {
		return "", fmt.Errorf("nom de compte local inattendu : %q", nom)
	}
	return filepath.Join(DossierSecrets, nom+".secret"), nil
}

// LireSecret rend le mot de passe gardé pour un compte local, et s'il existe.
func LireSecret(nom string) (string, bool, error) {
	chemin, err := cheminSecret(nom)
	if err != nil {
		return "", false, err
	}
	brut, err := os.ReadFile(chemin)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("lecture du secret de %s : %w", nom, err)
	}
	if deproteger == nil {
		return "", false, errors.New("garde des secrets indisponible sur ce système")
	}
	clair, err := deproteger(brut)
	if err != nil {
		return "", false, fmt.Errorf("secret de %s indéchiffrable : %w", nom, err)
	}
	s := string(clair)
	effacer(clair)
	if len(s) != LongueurMotDePasseLocal || !motDePasseComplet(s) {
		return "", false, fmt.Errorf("secret de %s illisible (forme inattendue)", nom)
	}
	return s, true, nil
}

// EcrireSecret garde le mot de passe d'un compte local. Écrit à côté, puis
// renommé : un arrêt au milieu ne laisse pas un secret tronqué, que l'agent
// lirait ensuite comme le bon.
func EcrireSecret(nom, motDePasse string) error {
	chemin, err := cheminSecret(nom)
	if err != nil {
		return err
	}
	if proteger == nil {
		return errors.New("garde des secrets indisponible sur ce système")
	}
	clair := []byte(motDePasse)
	chiffre, err := proteger(clair)
	effacer(clair)
	if err != nil {
		return fmt.Errorf("chiffrement du secret de %s : %w", nom, err)
	}
	if err := os.MkdirAll(DossierSecrets, 0o700); err != nil {
		return fmt.Errorf("dossier des secrets : %w", err)
	}
	provisoire := chemin + ".nouveau"
	if err := os.WriteFile(provisoire, chiffre, 0o600); err != nil {
		return fmt.Errorf("écriture du secret de %s : %w", nom, err)
	}
	if err := os.Rename(provisoire, chemin); err != nil {
		_ = os.Remove(provisoire)
		return fmt.Errorf("écriture du secret de %s : %w", nom, err)
	}
	return nil
}

func effacer(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// --- la décision ----------------------------------------------------------------

// Geste : ce que le provisionnement doit faire du mot de passe du compte.
type Geste int

const (
	// GesteAucun : le compte existe et le secret gardé l'ouvre. Rien à poser —
	// c'est le cas ordinaire, et c'est ce qui préserve les secrets DPAPI.
	GesteAucun Geste = iota
	// GesteCreer : le compte n'existe pas ; il est créé avec le secret.
	GesteCreer
	// GestePoser : le compte existe mais le secret ne l'ouvre pas (compte d'avant
	// le 195, mot de passe changé hors de Vaultaire, secret perdu) : il est posé.
	GestePoser
)

// decider tranche, sans appel système.
//
//	existe     le compte local existe
//	connu      un secret était gardé (sinon il vient d'être tiré)
//	ouvre      le secret ouvre le compte ; nil quand on n'a pas pu le savoir
//	           (droit d'ouverture réseau refusé, compte verrouillé…)
//
// Un « je ne sais pas » ne fait PAS poser : remettre à zéro le mot de passe
// d'un compte perd ses secrets DPAPI, et ce serait à chaque connexion.
func decider(existe, connu bool, ouvre *bool) Geste {
	switch {
	case !existe:
		return GesteCreer
	case !connu:
		return GestePoser
	case ouvre != nil && !*ouvre:
		return GestePoser
	default:
		return GesteAucun
	}
}
