package localusermanagement

import (
	"fmt"
	"os"
	"strings"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Le droit d'administration d'un compte du domaine — TO-DO 197.
//
// # Qui gère le compte
//
// L'agent, seul. Le module PAM faisait le même travail juste après lui, à chaque
// connexion : `usermod -aG` ou `gpasswd -d` sur le groupe d'administration, que
// l'appartenance change ou non. L'agent, lui, ne connaissait que `wheel` — donc
// rien sur Debian et Ubuntu — et ne retirait jamais un compte qui avait perdu
// son droit. Les deux moitiés réunies ici font ce qu'aucune ne faisait seule.
//
// # Le groupe
//
// Le premier qui EXISTE parmi groupesAdministration : `sudo` (Debian, Ubuntu),
// `wheel` (Rocky, RHEL), `admin` (anciens Ubuntu). Le module PAM essayait aussi
// `staff` et `root` : aucun des deux ne donne `sudo` dans une configuration
// ordinaire — `staff` donne l'écriture dans /usr/local sur Debian, ce qui n'a
// rien d'un droit d'administration voulu. Ils sont écartés.
//
// Aucun groupe n'est CRÉÉ. Le module créait `sudo` quand aucun n'existait ; un
// groupe que la configuration de sudo ne nomme pas ne donnerait rien, et l'agent
// ne crée pas de groupe hors de la synchronisation du domaine.
//
// # À chaque connexion, mais sans écriture inutile
//
// L'appartenance est lue, puis /etc/group n'est réécrit que si elle doit
// CHANGER. C'est le cas de presque aucune connexion.
var groupesAdministration = []string{"sudo", "wheel", "admin"}

// GroupeAdministration rend le groupe d'administration de la machine, ou ""
// s'il n'y en a aucun.
func GroupeAdministration() (string, error) {
	contenu, err := os.ReadFile(groupPath())
	if err != nil {
		return "", err
	}
	for _, g := range groupesAdministration {
		if _, existe := membresDuGroupe(string(contenu), g); existe {
			return g, nil
		}
	}
	return "", nil
}

// AppliquerDroitAdministration aligne l'appartenance du compte au groupe
// d'administration sur ce que le core vient de dire.
//
// Rend le groupe concerné et vrai si /etc/group a été modifié.
func AppliquerDroitAdministration(username string, isAdmin bool) (string, bool, error) {
	if username == "" || strings.ContainsAny(username, ":,\n\r \t") {
		return "", false, fmt.Errorf("nom de compte %q refusé pour le groupe d'administration", username)
	}

	// Le même verrou que les groupes du domaine : les deux réécrivent
	// /etc/group, et deux lectures-réécritures croisées perdraient l'une des
	// deux modifications.
	groupMapMu.Lock()
	defer groupMapMu.Unlock()

	contenu, err := os.ReadFile(groupPath())
	if err != nil {
		return "", false, err
	}
	groupe := ""
	var membres []string
	for _, g := range groupesAdministration {
		if m, existe := membresDuGroupe(string(contenu), g); existe {
			groupe, membres = g, m
			break
		}
	}
	if groupe == "" {
		if isAdmin {
			return "", false, fmt.Errorf("aucun groupe d'administration (%s) sur cette machine",
				strings.Join(groupesAdministration, ", "))
		}
		return "", false, nil
	}

	membre := contient(membres, username)
	switch {
	case isAdmin && !membre:
		if _, err := addUserToGroupManual(groupe, username); err != nil {
			return groupe, false, err
		}
		logs.Write_log("INFO", fmt.Sprintf("%s ajouté au groupe d'administration %s", username, groupe))
		return groupe, true, nil
	case !isAdmin && membre:
		if err := retirerDuGroupe(groupe, username); err != nil {
			return groupe, false, err
		}
		logs.Write_log("INFO", fmt.Sprintf(
			"%s retiré du groupe d'administration %s (n'est plus administrateur dans l'annuaire)", username, groupe))
		return groupe, true, nil
	}
	return groupe, false, nil
}

// membresDuGroupe lit la ligne d'un groupe : ses membres, et s'il existe.
func membresDuGroupe(contenu, groupe string) ([]string, bool) {
	for _, ligne := range strings.Split(contenu, "\n") {
		if !strings.HasPrefix(ligne, groupe+":") {
			continue
		}
		champs := strings.Split(ligne, ":")
		if len(champs) < 4 {
			return nil, true
		}
		return decouper(champs[3]), true
	}
	return nil, false
}
