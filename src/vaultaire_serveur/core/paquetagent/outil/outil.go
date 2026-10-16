// Package outil porte les sous-commandes du binaire du core qui produisent et
// signent les manifestes de paquet d'agent — TO-DO 113.
//
//	vaultaire_serveur --package-manifest <archive>            manifestes NON signés (CI)
//	vaultaire_serveur --sign-package <archive>                 signés par pkg_signing (base)
//	vaultaire_serveur --sign-package <archive> --key <pem>     signés hors ligne
//	vaultaire_serveur --pkg-key show                           clé publique et empreinte
//	vaultaire_serveur --pkg-key export <fichier>               clé privée, dans un fichier 0600
//	vaultaire_serveur --pkg-key forget-private --confirm       passage au mode hors ligne
//
// # Qui signe : le core qui ADOPTE une release
//
// La release (CI) ne détient la clé d'aucun cluster : chaque installation a la
// sienne, générée à son premier démarrage. La CI produit donc le manifeste NON
// signé, à côté des archives ; le core le recalcule depuis l'archive, refuse
// s'il diffère, et le signe. Sa signature dit « ce cluster accepte ces
// octets » — c'est le site, pas l'amont, qui décide de ce que son parc
// installe.
//
// # Pourquoi des options du binaire, et pas une commande vlt
//
// Une commande vlt est une ligne de texte envoyée au core : elle ne transporte
// pas une archive de plusieurs dizaines de Mo. Signer demande l'archive, sur
// l'hôte du core — `docker exec vaultaire-ad /opt/vaultaire/bin/vaultaire_serveur
// --sign-package …`. Le dépôt dans Nexus (point 114) viendra s'y brancher.
package outil

import (
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"strings"

	"vaultaire/core/paquetagent"
)

// Cles est l'accès à la clé en base. Remplaçable par les tests, et ouvert
// seulement quand une sous-commande en a besoin : produire un manifeste non
// signé ne demande ni configuration ni base — c'est ce que fait la CI.
type Cles struct {
	Privee      func() (*rsa.PrivateKey, error)
	PubliquePEM func() (string, error)
	Oublier     func() error
}

// EstCommande dit si les arguments désignent une de ces sous-commandes.
func EstCommande(args []string) bool {
	for _, a := range args {
		switch a {
		case "--package-manifest", "--sign-package", "--pkg-key":
			return true
		}
	}
	return false
}

// Executer traite la sous-commande et rend le code de sortie.
//
// ouvrir donne l'accès à la clé en base ; il n'est appelé que si la
// sous-commande en a besoin.
func Executer(args []string, sortie, erreurs io.Writer, ouvrir func() (Cles, error)) int {
	echec := func(format string, a ...any) int {
		fmt.Fprintf(erreurs, "erreur : "+format+"\n", a...)
		return 1
	}
	if len(args) < 2 {
		fmt.Fprint(erreurs, Aide)
		return 2
	}

	switch args[0] {
	case "--package-manifest":
		if len(args) != 2 {
			fmt.Fprint(erreurs, Aide)
			return 2
		}
		manifestes, err := lireArchive(args[1])
		if err != nil {
			return echec("%v", err)
		}
		for _, m := range manifestes {
			chemin := paquetagent.NomManifeste(args[1], m)
			corps, _ := m.Corps()
			if err := ecrire(chemin, corps); err != nil {
				return echec("%v", err)
			}
			fmt.Fprintf(sortie, "%s  (%s %s, non signé)\n", chemin, m.Version, m.Plateforme)
		}
		return 0

	case "--sign-package":
		archive, fichierCle := args[1], ""
		switch {
		case len(args) == 2:
		case len(args) == 4 && args[2] == "--key":
			fichierCle = args[3]
		default:
			fmt.Fprint(erreurs, Aide)
			return 2
		}
		return signer(archive, fichierCle, sortie, erreurs, ouvrir)

	case "--pkg-key":
		return cle(args[1:], sortie, erreurs, ouvrir)
	}
	fmt.Fprint(erreurs, Aide)
	return 2
}

func signer(archive, fichierCle string, sortie, erreurs io.Writer, ouvrir func() (Cles, error)) int {
	echec := func(format string, a ...any) int {
		fmt.Fprintf(erreurs, "erreur : "+format+"\n", a...)
		return 1
	}
	manifestes, err := lireArchive(archive)
	if err != nil {
		return echec("%v", err)
	}

	// Le manifeste publié par la CI, s'il est là, doit être CELUI qu'on
	// recalcule. Un écart veut dire que l'archive n'est pas celle que la
	// release a décrite : on ne signe pas.
	for _, m := range manifestes {
		corps, _ := m.Corps()
		existant, err := os.ReadFile(paquetagent.NomManifeste(archive, m))
		switch {
		case os.IsNotExist(err):
		case err != nil:
			return echec("lecture du manifeste publié : %v", err)
		case string(existant) != corps:
			return echec("%s ne correspond pas à l'archive : elle n'est pas celle que la "+
				"release décrit — rien n'est signé", paquetagent.NomManifeste(archive, m))
		}
	}

	var privee *rsa.PrivateKey
	var publiques []*rsa.PublicKey
	if fichierCle != "" {
		contenu, err := os.ReadFile(fichierCle)
		if err != nil {
			return echec("lecture de la clé : %v", err)
		}
		if privee, err = paquetagent.LireClePrivee(contenu); err != nil {
			return echec("%v", err)
		}
		publiques = []*rsa.PublicKey{&privee.PublicKey}
	} else {
		cles, err := ouvrir()
		if err != nil {
			return echec("%v", err)
		}
		if privee, err = cles.Privee(); err != nil {
			return echec("%v", err)
		}
		pemPublique, err := cles.PubliquePEM()
		if err != nil {
			return echec("%v", err)
		}
		// La relecture se fait avec la PUBLIQUE en base — celle que les machines
		// ont reçue — et non avec celle qu'on déduit de la privée : une base
		// où les deux ne vont plus ensemble produirait des paquets que tout le
		// parc refuserait.
		if publiques, err = paquetagent.LireClesPubliques([]byte(pemPublique)); err != nil {
			return echec("%v", err)
		}
	}

	for _, m := range manifestes {
		corps, _ := m.Corps()
		env, err := paquetagent.Signer(corps, privee)
		if err != nil {
			return echec("%v", err)
		}
		if _, err := paquetagent.Verifier(corps, env, publiques); err != nil {
			return echec("la signature produite ne se vérifie pas avec la clé publique "+
				"déposée sur les machines (%v) — rien n'est écrit", err)
		}
		chemin := paquetagent.NomManifeste(archive, m)
		if err := ecrire(chemin, corps); err != nil {
			return echec("%v", err)
		}
		if err := ecrire(chemin+".sig", env.Texte()); err != nil {
			return echec("%v", err)
		}
		fmt.Fprintf(sortie, "%s.sig  (%s %s, clé %s)\n", chemin, m.Version, m.Plateforme, env.EmpreinteCle)
	}
	return 0
}

func cle(args []string, sortie, erreurs io.Writer, ouvrir func() (Cles, error)) int {
	echec := func(format string, a ...any) int {
		fmt.Fprintf(erreurs, "erreur : "+format+"\n", a...)
		return 1
	}
	if len(args) == 0 {
		fmt.Fprint(erreurs, Aide)
		return 2
	}
	sousCommande := args[0]
	bonneForme := false
	switch sousCommande {
	case "show":
		bonneForme = len(args) == 1
	case "export":
		bonneForme = len(args) == 2
	case "forget-private":
		if len(args) == 1 {
			return echec("forget-private efface la clé privée de la base : ajoutez --confirm, " +
				"APRÈS l'avoir exportée et rangée ailleurs (--pkg-key export <fichier>)")
		}
		bonneForme = len(args) == 2 && args[1] == "--confirm"
	}
	if !bonneForme {
		fmt.Fprint(erreurs, Aide)
		return 2
	}

	cles, err := ouvrir()
	if err != nil {
		return echec("%v", err)
	}
	switch sousCommande {
	case "show":
		pemPublique, err := cles.PubliquePEM()
		if err != nil {
			return echec("%v", err)
		}
		pubs, err := paquetagent.LireClesPubliques([]byte(pemPublique))
		if err != nil {
			return echec("%v", err)
		}
		empreinte, _ := paquetagent.EmpreinteCle(pubs[0])
		enLigne := "oui — ce core signe"
		if _, err := cles.Privee(); err != nil {
			enLigne = "non — signature hors ligne (--sign-package --key)"
		}
		fmt.Fprintf(sortie, "Empreinte   : %s\nClé privée  : %s\n\n%s", empreinte, enLigne, pemPublique)
		if !strings.HasSuffix(pemPublique, "\n") {
			fmt.Fprintln(sortie)
		}
	case "export":
		// Dans un FICHIER, et pas sur la sortie standard : le journal du core
		// y écrit aussi, et une ligne de journal au milieu d'une clé redirigée
		// donnerait un fichier qu'on croit sauvegardé et qui ne se relit pas.
		privee, err := cles.Privee()
		if err != nil {
			return echec("%v", err)
		}
		if err := ecrirePEMPrivee(args[1], privee); err != nil {
			return echec("%v", err)
		}
		fmt.Fprintf(sortie, "Clé privée écrite dans %s (0600). Quiconque la détient fait accepter "+
			"ses paquets à tout le parc : rangez-la hors ligne, puis effacez ce fichier.\n", args[1])
	case "forget-private":
		if err := cles.Oublier(); err != nil {
			return echec("%v", err)
		}
		fmt.Fprintln(sortie, "Clé privée retirée de la base. La clé publique reste, et les "+
			"machines ne voient aucun changement. Signez désormais avec --sign-package <archive> --key <fichier>.")
	}
	return 0
}

func lireArchive(chemin string) ([]paquetagent.Manifeste, error) {
	f, err := os.Open(chemin)
	if err != nil {
		return nil, fmt.Errorf("ouverture de l'archive : %w", err)
	}
	defer func() { _ = f.Close() }()
	return paquetagent.DepuisArchive(f)
}

// ecrire écrit par un fichier temporaire puis rename : un manifeste ou une
// signature à moitié écrits ne doivent jamais être lisibles sous leur nom.
func ecrire(chemin, contenu string) error {
	tmp := chemin + ".tmp"
	if err := os.WriteFile(tmp, []byte(contenu), 0o644); err != nil {
		return fmt.Errorf("écriture de %s : %w", chemin, err)
	}
	if err := os.Rename(tmp, chemin); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("écriture de %s : %w", chemin, err)
	}
	return nil
}

// Aide est le mode d'emploi, rendu sur une erreur de syntaxe.
const Aide = `Paquets d'agent (TO-DO 113) :
  vaultaire_serveur --package-manifest <archive>         manifestes non signés, à côté de l'archive
  vaultaire_serveur --sign-package <archive>             signe avec la clé pkg_signing de la base
  vaultaire_serveur --sign-package <archive> --key <pem> signe hors ligne, sans base
  vaultaire_serveur --pkg-key show                       empreinte et clé publique
  vaultaire_serveur --pkg-key export <fichier>           clé privée dans un fichier (0600, jamais écrasé)
  vaultaire_serveur --pkg-key forget-private --confirm   retire la clé privée de la base
`
