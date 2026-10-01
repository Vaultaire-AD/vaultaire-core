package localusermanagement

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Retrait des comptes du domaine restés inutilisés.
//
// # Ce qui ne marchait pas
//
// Le ménage cherchait les comptes dont le GECOS contient
// « vaultaire_user_account ». Or ProvisionVaultaireUser écrit « <compte>@vaultaire ».
// Aucun compte créé par cet agent n'a jamais porté la chaîne cherchée : la
// fonction parcourait /etc/passwd et ne retenait rien, tous les jours, depuis
// toujours.
//
// # Pourquoi uid.map plutôt qu'une autre chaîne dans le GECOS
//
// Corriger la chaîne aurait remis le même défaut en place, décalé d'une
// version : le GECOS est un champ libre que l'administrateur peut réécrire, que
// les outils de la distribution modifient, et qui ne dit rien de ce que l'agent
// a réellement créé.
//
// La carte des UID, elle, EST la liste des comptes que cet agent a
// provisionnés — c'est sa raison d'être, et le module NSS s'en sert déjà comme
// source de vérité. Un compte absent de la carte n'est pas à nous, et rien ne
// justifierait de le supprimer.
//
// # Les trois conditions, et pourquoi il en faut trois
//
// Un compte n'est retiré que s'il est À LA FOIS dans la carte, dans
// /etc/passwd, et porté par le MÊME UID dans les deux. La carte seule ne
// suffit pas : elle adopte l'UID d'un compte local préexistant
// (EnsureUIDMapping), si bien qu'un compte créé à la main avant Vaultaire peut
// y figurer. L'égalité des UID est ce qui distingue « ce compte est le nôtre »
// de « ce compte porte un nom que nous connaissons ».
//
// # La règle « garder au moins trois comptes » a été retirée
//
// Elle empêchait toute suppression tant qu'il restait moins de quatre comptes
// du domaine — c'est-à-dire sur exactement les machines où le ménage sert :
// un poste de travail en compte deux ou trois. Et elle ne protégeait rien : les
// comptes épargnés étaient ceux que l'ordre de /etc/passwd plaçait en dernier,
// pas ceux qui méritaient de rester.
//
// Ce qui protège désormais est la triple condition ci-dessus : on ne touche
// qu'aux comptes que cet agent a créés.

// InactiviteAvantRetrait : au-delà, un compte du domaine est retiré de la
// machine.
//
// Quatre jours, la valeur d'origine. Le compte n'est pas supprimé de
// l'annuaire : il sera recréé à la connexion suivante, avec le même UID, que la
// carte conserve jusqu'au retrait de l'entrée.
const InactiviteAvantRetrait = 96 * time.Hour

// derniereConnexion est remplaçable en test : elle appelle `lastlog`, absent
// des environnements de compilation, et la seule chose qu'on veuille éprouver
// ici est la DÉCISION, pas la commande.
var derniereConnexion = derniereConnexionLastlog

// supprimerCompte est remplaçable pour la même raison : un test ne lance pas
// `userdel` sur la machine qui l'exécute.
var supprimerCompte = supprimerCompteUserdel

// DeleteUser_Vaultaire_Past_4Days_withoutconnection retire les comptes du
// domaine restés sans connexion.
//
// Ne rend aucune erreur : c'est une tâche de fond, et chaque compte est traité
// indépendamment des autres. Ce qui échoue est journalisé, ce qui reste est
// traité.
func DeleteUser_Vaultaire_Past_4Days_withoutconnection() {
	candidats, err := comptesDuDomaine()
	if err != nil {
		// Journalisé, PAS fatal. La version précédente appelait log.Fatalf sur
		// un /etc/passwd illisible : une tâche de ménage arrêtait alors l'agent
		// entier — donc l'authentification de toute la machine — pour un
		// fichier qu'elle n'avait qu'à relire au tour suivant.
		logs.Write_log("ERROR", "ménage des comptes : "+err.Error())
		return
	}
	if len(candidats) == 0 {
		logs.Write_log("DEBUG", "ménage des comptes : aucun compte du domaine sur cette machine")
		return
	}

	retires := 0
	for _, nom := range candidats {
		inactif, motif, err := compteInactif(nom)
		if err != nil {
			logs.Write_log("WARNING", fmt.Sprintf(
				"ménage des comptes : dernière connexion de %s inconnue, compte conservé : %v", nom, err))
			continue
		}
		if !inactif {
			continue
		}

		if err := supprimerCompte(nom); err != nil {
			logs.Write_log("WARNING", fmt.Sprintf(
				"ménage des comptes : suppression de %s impossible : %v", nom, err))
			continue
		}

		// L'entrée de la carte part AVEC le compte, et seulement après lui.
		//
		// La garder laisserait un UID réservé à un compte qui n'existe plus, et
		// la carte finirait par décrire un parc de comptes fantômes. La retirer
		// AVANT la suppression aurait l'effet inverse et bien pire : un userdel
		// en échec laisserait sur la machine un compte dont plus rien ne tient
		// l'UID, qui pourrait être réattribué à quelqu'un d'autre — lequel
		// hériterait de ses fichiers.
		if err := RemoveUIDMapping(nom); err != nil {
			logs.Write_log("WARNING", fmt.Sprintf(
				"ménage des comptes : %s supprimé, mais son entrée d'uid.map reste : %v", nom, err))
		}

		retires++
		logs.Write_log("INFO", fmt.Sprintf(
			"ménage des comptes : %s retiré (%s)", nom, motif))
	}

	logs.Write_log("INFO", fmt.Sprintf(
		"ménage des comptes : %d compte(s) examiné(s), %d retiré(s)", len(candidats), retires))
}

// comptesDuDomaine rend les comptes que CET agent a provisionnés.
//
// L'intersection de la carte et de /etc/passwd, à UID égal. Voir l'en-tête du
// fichier pour la raison des trois conditions.
func comptesDuDomaine() ([]string, error) {
	carte, err := LoadUIDMap()
	if err != nil {
		return nil, fmt.Errorf("uid.map illisible : %w", err)
	}
	if len(carte) == 0 {
		return nil, nil
	}

	locaux, err := comptesLocaux()
	if err != nil {
		return nil, err
	}

	var noms []string
	for nom, entree := range carte {
		uidLocal, present := locaux[nom]
		if !present {
			// Dans la carte, absent de la machine : il n'y a rien à supprimer.
			// L'entrée reste — elle tient l'UID, et c'est ce qui rend l'identité
			// stable si le compte est recréé.
			continue
		}
		if uidLocal != entree.UID {
			logs.Write_log("WARNING", fmt.Sprintf(
				"ménage des comptes : %s porte l'UID %d dans /etc/passwd et %d dans uid.map — "+
					"compte laissé en place", nom, uidLocal, entree.UID))
			continue
		}
		noms = append(noms, nom)
	}
	return noms, nil
}

// comptesLocaux lit /etc/passwd et rend nom → UID.
//
// Passe par passwdPath() : les tests ne peuvent pas écrire dans /etc, et un
// test qui lirait le /etc/passwd de la machine qui l'exécute ne mesurerait
// rien de reproductible.
func comptesLocaux() (map[string]int, error) {
	f, err := os.Open(passwdPath())
	if err != nil {
		return nil, fmt.Errorf("lecture de %s : %w", passwdPath(), err)
	}
	defer func() { _ = f.Close() }()

	comptes := map[string]int{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		champs := strings.Split(scanner.Text(), ":")
		if len(champs) < 3 {
			continue
		}
		uid, err := strconv.Atoi(strings.TrimSpace(champs[2]))
		if err != nil {
			continue
		}
		comptes[champs[0]] = uid
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parcours de %s : %w", passwdPath(), err)
	}
	return comptes, nil
}

// compteInactif dit si un compte dépasse le délai, et pourquoi.
func compteInactif(nom string) (bool, string, error) {
	derniere, jamais, err := derniereConnexion(nom)
	if err != nil {
		return false, "", err
	}
	if jamais {
		return true, "jamais connecté", nil
	}

	depuis := time.Since(derniere)
	if depuis < InactiviteAvantRetrait {
		return false, "", nil
	}
	return true, fmt.Sprintf("sans connexion depuis %d jour(s)", int(depuis.Hours()/24)), nil
}

// derniereConnexionLastlog interroge `lastlog`.
//
// # LC_ALL=C, et ce n'est pas un détail
//
// La date est analysée avec le format « Mon Jan 2 15:04:05 2006 », c'est-à-dire
// des noms de jour et de mois ANGLAIS. Sur une machine dont la locale est
// française — le cas courant du parc visé — `lastlog` écrit « lun. sept. 22 »,
// l'analyse échoue, et le compte est jugé actif pour toujours. Le ménage se
// taisait donc aussi sur les machines où il aurait trouvé quelque chose.
//
// Le même argument vaut pour « **Never logged in** », comparé mot pour mot.
func derniereConnexionLastlog(nom string) (time.Time, bool, error) {
	cmd := exec.Command("lastlog", "-u", nom)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")

	sortie, err := cmd.Output()
	if err != nil {
		return time.Time{}, false, fmt.Errorf("lastlog : %w", err)
	}

	lignes := strings.Split(string(sortie), "\n")
	if len(lignes) < 2 {
		return time.Time{}, false, fmt.Errorf("lastlog : sortie inattendue pour %s", nom)
	}
	return LireLigneLastlog(lignes[1])
}

// LireLigneLastlog analyse la ligne de résultat de `lastlog`.
//
// Exportée pour être éprouvée : c'est l'analyse d'une sortie de commande, donc
// exactement la partie qui casse en silence quand l'environnement change.
//
// Rend (date, jamaisConnecté, erreur). Une ligne qu'on ne sait pas lire est une
// ERREUR et non « jamais connecté » : confondre les deux ferait supprimer un
// compte actif dès que le format de `lastlog` change d'un mot.
func LireLigneLastlog(ligne string) (time.Time, bool, error) {
	if strings.Contains(ligne, "**Never logged in**") {
		return time.Time{}, true, nil
	}

	champs := strings.Fields(ligne)
	if len(champs) < 5 {
		return time.Time{}, false, fmt.Errorf("ligne lastlog illisible : %q", ligne)
	}

	// Les cinq derniers champs portent la date ; ce qui précède est le nom, le
	// port et l'adresse, dont le nombre varie.
	date := strings.Join(champs[len(champs)-5:], " ")
	t, err := time.Parse("Mon Jan 2 15:04:05 2006", date)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("date lastlog illisible : %q", date)
	}
	return t, false, nil
}

// supprimerCompteUserdel retire le compte et son répertoire personnel.
//
// `userdel` refuse un compte dont une session est ouverte, et c'est voulu : on
// remonte son refus tel quel plutôt que de forcer. Un compte inactif depuis
// quatre jours sur lequel quelqu'un vient d'ouvrir une session n'est plus
// inactif.
func supprimerCompteUserdel(nom string) error {
	sortie, err := exec.Command("userdel", "-r", nom).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v : %s", err, strings.TrimSpace(string(sortie)))
	}
	return nil
}
