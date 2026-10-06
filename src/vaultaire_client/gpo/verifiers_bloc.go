package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Le bloc que Vaultaire tient dans un fichier de l'utilisateur — TO-DO 135.
//
// # Ce que cela surveille
//
// Trois sortes de fichiers d'un `HOME` portent un morceau de politique sans lui
// appartenir : les fichiers de démarrage du shell (`.bashrc`, `.bash_profile`,
// `.profile`, `.zshrc`), où `user_env` pose la ligne qui charge
// `.vaultaire_env`, et `~/.ssh/config`, où `user_ssh_client_config` pose une
// entrée `Host` par alias.
//
// Le reste de ces fichiers est à la personne, et la politique n'a rien à en
// dire. Ce qu'elle exige, c'est que SON bloc y soit, intact — ou n'y soit pas,
// quand elle le retire.
//
// # Pourquoi une attente et non une entrée d'inventaire
//
// L'inventaire des fichiers compare un hachage de fichier ENTIER. L'employer
// ici aurait déclaré « en écart » quiconque ajoute un alias à son `.bashrc`, et
// l'aurait « corrigé » à la connexion suivante. Une attente d'état porte
// exactement la question posée : ce bloc, ce contenu.
//
// Elle s'attribue et se rejoue comme les autres : le bloc retiré fait oublier
// l'empreinte du module, et le cycle qui suit le repose.

// CheckFileBlock vérifie le bloc balisé qu'un module tient dans un fichier.
const (
	CheckFileBlock = "file_block"
)

// blocEnvironnement désigne le bloc de sourcing posé par `user_env`, délimité
// par les marqueurs généraux de Vaultaire.
const blocEnvironnement = "env"

// prefixeBlocSSH ouvre l'identifiant d'un bloc de `~/.ssh/config` : un par
// alias, donc un par module.
const prefixeBlocSSH = "ssh:"

// separateurBloc sépare le chemin de l'identifiant du bloc dans la cible.
//
// « #bloc: » et non la barre verticale des ACL : la cible part telle quelle
// dans le rapport 05_15, où la barre est le séparateur de champs et se trouve
// donc réécrite en « %7C ». `/home/alice/.bashrc#bloc:env` se lit sans notice.
const separateurBloc = "#bloc:"

func init() {
	registerChecker(CheckFileBlock, verifierBloc)
}

// marqueursDuBloc rend les deux lignes qui délimitent un bloc.
func marqueursDuBloc(bloc string) (debut, fin string, ok bool) {
	switch {
	case bloc == blocEnvironnement:
		return vaultaireMarkerStart, vaultaireMarkerEnd, true
	case strings.HasPrefix(bloc, prefixeBlocSSH) && len(bloc) > len(prefixeBlocSSH):
		alias := strings.TrimPrefix(bloc, prefixeBlocSSH)
		return marqueursSSH(alias)
	}
	return "", "", false
}

// marqueursSSH rend les balises d'un alias de `~/.ssh/config`.
//
// Une seule définition, employée par l'appliqueur qui les écrit et par le
// vérificateur qui les relit : deux chaînes construites séparément finiraient
// par différer d'un espace, et le bloc serait déclaré absent pour toujours.
func marqueursSSH(alias string) (debut, fin string, ok bool) {
	if alias == "" {
		return "", "", false
	}
	return "# >>> vaultaire-gpo:" + alias + " >>>", "# <<< vaultaire-gpo:" + alias + " <<<", true
}

// extraireBloc rend le corps d'un bloc — les lignes entre ses deux balises.
//
// « Présent » veut dire OUVERT ET FERMÉ. Une balise d'ouverture sans fermeture
// est un fichier tronqué ou édité à la main : le bloc n'est pas dans l'état où
// la politique l'a laissé, et c'est ce que le vérificateur doit dire.
//
// Les balises sont comparées sans leurs blancs de bord, comme le fait
// removeMarkedBlock : une indentation ajoutée par un éditeur ne fait pas
// disparaître un bloc.
func extraireBloc(contenu, debut, fin string) (corps string, present bool) {
	var lignes []string
	dedans := false
	for _, ligne := range strings.Split(contenu, "\n") {
		nette := strings.TrimSpace(ligne)
		switch {
		case !dedans && nette == debut:
			dedans = true
			lignes = lignes[:0]
		case dedans && nette == fin:
			return strings.Join(lignes, "\n"), true
		case dedans:
			lignes = append(lignes, ligne)
		}
	}
	return "", false
}

func hacherBloc(corps string) string {
	somme := sha256.Sum256([]byte(corps))
	return hex.EncodeToString(somme[:])
}

// verifierBloc constate qu'un bloc est là, tel qu'il a été posé — ou qu'il n'y
// est pas, quand la politique le retire.
//
// Le fichier est relu par lireFichierUtilisateur : sans suivre un seul lien, et
// seulement s'il s'agit d'un fichier ordinaire du compte. Un lien planté à sa
// place n'est donc jamais lu ; il est SIGNALÉ, parce que le fichier que la
// politique a écrit était ordinaire et ne l'est plus.
func verifierBloc(c SystemCheck) (bool, string, error) {
	// La PREMIÈRE occurrence : ce qui suit le séparateur est l'identifiant du
	// bloc, et un alias SSH — choisi par un administrateur — peut contenir
	// n'importe quoi, le séparateur compris. Un chemin de fichier de démarrage,
	// lui, ne le contient pas.
	i := strings.Index(c.Target, separateurBloc)
	if i <= 0 {
		return false, "", fmt.Errorf("cible de bloc illisible")
	}
	chemin, bloc := c.Target[:i], c.Target[i+len(separateurBloc):]
	debut, fin, ok := marqueursDuBloc(bloc)
	if !ok {
		return false, "", fmt.Errorf("bloc %q inconnu de cet agent", bloc)
	}

	attendu := champsAttendus(c.Expect)
	compte := attendu["compte"]
	if compte == "" {
		return false, "", fmt.Errorf("attente de bloc sans compte")
	}
	home, err := resolveHomeDir(compte)
	if err != nil {
		return false, "", err
	}
	uid, _, err := resolveUserIDs(compte)
	if err != nil {
		return false, "", err
	}

	veutAbsent := attendu["etat"] == "absent"

	contenu, existe, err := lireFichierUtilisateur(home, chemin, uid)
	switch {
	case err != nil && errors.Is(err, ErrCheminSuspect):
		// Constat, et non incertitude : il y a là autre chose qu'un fichier
		// ordinaire du compte.
		return false, "le fichier n'est plus un fichier ordinaire du compte", nil
	case err != nil:
		return false, "", err
	case !existe && veutAbsent:
		return true, "", nil
	case !existe:
		return false, "fichier supprime", nil
	}

	corps, present := extraireBloc(contenu, debut, fin)
	switch {
	case veutAbsent && present:
		return false, "bloc Vaultaire retabli alors que la politique le retire", nil
	case veutAbsent:
		return true, "", nil
	case !present:
		return false, "bloc Vaultaire retire ou tronque", nil
	case hacherBloc(corps) != attendu["sha256"]:
		return false, "bloc Vaultaire modifie", nil
	}
	return true, "", nil
}
