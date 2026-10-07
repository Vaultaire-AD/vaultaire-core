//go:build !linux

package gpo

import (
	"errors"
	"fmt"
	"os"
)

// La traversée sûre du scope utilisateur n'existe que sur Linux — TO-DO 97.
//
// # Pourquoi un fichier de repli plutôt qu'aucun
//
// L'agent est un programme Linux : il pose des comptes locaux, écrit dans
// `/etc/shadow` et parle à PAM. Mais le paquet `gpo` COMPILAIT jusqu'ici pour
// tous les systèmes, et plusieurs outils de développement — `go vet` croisé,
// une analyse depuis un poste macOS — s'appuient sur ce fait.
//
// Le repli rend donc une erreur explicite plutôt que de faire échouer la
// compilation. Ce qu'il ne fait SURTOUT pas, c'est retomber sur `os.MkdirAll` et
// `os.Chown` : ce serait rétablir exactement la faille ailleurs, dans un chemin
// que personne ne relit parce qu'il ne tourne nulle part.
var ErrCheminSuspect = errors.New("chemin suspect sous le repertoire personnel")

// ErrProprietaireAutre distingue LA cause qu'on ne peut pas corriger seul.
//
// Un composant du chemin qui est un lien symbolique, c'est quelqu'un qui a posé
// un piège : on refuse, on journalise, et il n'y a rien d'autre à faire.
//
// Un répertoire qui EXISTAIT DÉJÀ et appartient à un autre compte, c'est autre
// chose : un `HOME` mal repris, un `chown` oublié, un compte recréé sous le même
// nom avec un uid neuf. Le refus reste le bon réflexe — reprendre un répertoire
// dont on ne sait pas d'où il vient, en root, est précisément ce que le point 97
// a fermé — mais le remède n'est pas le même, et le message ne doit pas accuser
// l'utilisateur d'avoir planté un lien quand il n'a rien fait.
//
// ATTENTION : elle n'enveloppe PAS ErrCheminSuspect — c'est une sentinelle nue.
// Les deux ne cohabitent que parce que le site d'appel les joint par un DOUBLE
// « %w ». Un futur site qui n'emploierait que celle-ci produirait une erreur que
// « errors.Is(err, ErrCheminSuspect) » ne verrait pas, et qui passerait donc à
// travers tout le traitement du cas général, en silence. Ne l'employer que
// conjointement.
var ErrProprietaireAutre = errors.New("repertoire preexistant appartenant a un autre compte")

const indisponible = "l'ecriture sure du scope utilisateur demande les appels " +
	"openat/renameat de Linux ; ce systeme n'est pas pris en charge"

func ecrireFichierUtilisateur(_, chemin, _ string, _ os.FileMode, _, _ int) error {
	return fmt.Errorf("%s (%s)", indisponible, chemin)
}

func preparerRepertoireUtilisateur(_, chemin string, _ os.FileMode, _, _ int) error {
	return fmt.Errorf("%s (%s)", indisponible, chemin)
}

func lireFichierUtilisateur(_, chemin string, _ int) (string, bool, error) {
	return "", false, fmt.Errorf("%s (%s)", indisponible, chemin)
}

func retirerSousHome(_, chemin string, _ int) (bool, error) {
	return false, fmt.Errorf("%s (%s)", indisponible, chemin)
}

func designerSousHome(_, chemin string, _ int) (*os.File, error) {
	return nil, fmt.Errorf("%s (%s)", indisponible, chemin)
}

var errObjetAbsent = errors.New("absent")

// etatSousHome : voir chemin_sur_linux.go.
type etatSousHome struct {
	Existe    bool
	Lien      bool
	Ordinaire bool
	Uid       int
	Mode      uint32
	SHA256    string
	TropGros  bool
}

func constaterSousHome(_, chemin string, _ int) (etatSousHome, error) {
	return etatSousHome{}, fmt.Errorf("%s (%s)", indisponible, chemin)
}

func lireLienSousHome(_, chemin string, _ int) (string, bool, bool, error) {
	return "", false, false, fmt.Errorf("%s (%s)", indisponible, chemin)
}
