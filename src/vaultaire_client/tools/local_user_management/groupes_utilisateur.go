package localusermanagement

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Appartenances de groupe posées par Vaultaire, et leur suivi.
//
// # Le problème
//
// Le serveur connaît les groupes d'un compte ; la machine ne les a jamais su.
// Un utilisateur retiré d'un groupe côté annuaire gardait donc son appartenance
// locale — et avec elle tout ce que ce groupe donnait sur le poste — jusqu'à ce
// que quelqu'un aille éditer `/etc/group` à la main.
//
// # Pourquoi un fichier d'état, et pas simplement « retirer ce qui n'est plus
// dans la liste »
//
// Parce que l'agent n'est pas seul sur cette machine. `/etc/group` contient des
// appartenances posées par l'administrateur local, par un paquet, par un
// installeur. Retirer un utilisateur de tout groupe absent de la liste du
// serveur effacerait tout cela — silencieusement, à la première connexion.
//
// L'agent ne retire donc QUE ce qu'il a lui-même ajouté. Ce fichier est la
// mémoire de ce qu'il a ajouté, exactement comme `uid.map` est la mémoire des
// identifiants qu'il a attribués.
//
// # Ce qu'il ne fait PAS
//
// Il ne CRÉE aucun groupe. Un groupe du domaine absent de la machine est
// simplement ignoré — l'appartenance est notée comme non posée, et le journal le
// dit. La création des groupes du domaine, avec sa plage de GID et sa politique
// de suppression, est un sujet à part entière : voir la spécification
// « Synchronisation des groupes de la machine » dans Protocole_Ducky.md.
//
// Poser une appartenance dans un groupe inexistant n'aurait aucun effet, et
// créer le groupe au passage lui donnerait un GID tiré au hasard que le reste du
// parc ne partagerait pas.

// Chemins, indirects pour que les tests puissent les déplacer.
//
// 0644 sur le fichier d'état, comme /etc/group lui-même : le contenu est de même
// nature — des noms, aucun secret — et une lecture sans privilège doit rester
// possible pour le diagnostic.
var (
	repertoireEtat = UIDMapDir
	fichierGroupes = "/etc/group"
)

func groupMapPath() string { return filepath.Join(repertoireEtat, "user_groups.map") }
func groupPath() string    { return fichierGroupes }

// groupMapMu sérialise les écritures.
//
// Deux sessions PAM simultanées de deux utilisateurs différents réécriraient
// sinon le fichier chacune à partir de sa propre lecture, et la dernière
// effacerait les appartenances de l'autre.
var groupMapMu sync.Mutex

// ChargerGroupesPoses lit les appartenances posées par l'agent.
//
// Un fichier absent n'est pas une erreur : c'est l'état d'une machine qui n'a
// encore rien posé.
//
// Une ligne malformée est ignorée plutôt que fatale. Le fichier est sur disque ;
// une ligne abîmée ne doit pas faire perdre les autres.
func ChargerGroupesPoses() (map[string][]string, error) {
	poses := map[string][]string{}

	f, err := os.Open(groupMapPath())
	if err != nil {
		if os.IsNotExist(err) {
			return poses, nil
		}
		return poses, fmt.Errorf("lecture de %s : %w", groupMapPath(), err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ligne := strings.TrimSpace(scanner.Text())
		if ligne == "" || strings.HasPrefix(ligne, "#") {
			continue
		}
		nom, liste, ok := strings.Cut(ligne, ":")
		if !ok || nom == "" {
			continue
		}
		poses[nom] = decouper(liste)
	}
	if err := scanner.Err(); err != nil {
		return poses, fmt.Errorf("parcours de %s : %w", groupMapPath(), err)
	}
	return poses, nil
}

// AppliquerGroupesUtilisateur aligne les appartenances locales sur la liste du
// serveur.
//
// Rend les groupes réellement posés — qui peuvent être moins nombreux que
// demandés, si certains n'existent pas localement.
//
// # L'ordre des opérations
//
// Les retraits AVANT les ajouts. Un groupe qui disparaît de la liste et un autre
// qui y entre au même moment sont deux gestes indépendants, mais commencer par
// retirer garantit qu'un incident au milieu laisse l'utilisateur avec MOINS de
// droits qu'attendu, jamais plus.
func AppliquerGroupesUtilisateur(username string, groupesVoulus []string) ([]string, error) {
	if username == "" {
		return nil, fmt.Errorf("nom d'utilisateur requis")
	}

	groupMapMu.Lock()
	defer groupMapMu.Unlock()

	poses, err := ChargerGroupesPoses()
	if err != nil {
		// L'état est illisible : on ne retire RIEN. Retirer sans savoir ce qu'on
		// a posé reviendrait à toucher aux appartenances de l'administrateur
		// local, ce que ce fichier existe précisément pour éviter.
		logs.Write_log("WARNING",
			"groupes : état illisible ("+err.Error()+"), aucun retrait effectué")
		poses = map[string][]string{}
	}

	voulus := normaliser(groupesVoulus)
	ancien := poses[username]

	// RETRAITS : ce que l'agent avait posé et qui n'est plus voulu.
	for _, g := range ancien {
		if contient(voulus, g) {
			continue
		}
		if err := retirerDuGroupe(g, username); err != nil {
			logs.Write_log("WARNING", fmt.Sprintf(
				"groupes : retrait de %s du groupe %s impossible : %v", username, g, err))
			continue
		}
		logs.Write_log("INFO", fmt.Sprintf(
			"groupes : %s retiré du groupe %s (retiré côté annuaire)", username, g))
	}

	// AJOUTS : seulement dans les groupes qui EXISTENT localement.
	//
	// L'existence n'est pas vérifiée à part : addUserToGroupManual rend « faux »
	// pour un groupe absent, sur la même lecture du fichier que l'inscription.
	// Deux lectures successives laisseraient un intervalle pendant lequel le
	// groupe peut disparaître, et l'appartenance serait comptée comme posée alors
	// qu'elle ne l'est pas.
	var effectifs []string
	for _, g := range voulus {
		pose, err := addUserToGroupManual(g, username)
		switch {
		case err != nil:
			logs.Write_log("WARNING", fmt.Sprintf(
				"groupes : inscription de %s dans %s impossible : %v", username, g, err))
		case !pose:
			logs.Write_log("DEBUG", fmt.Sprintf(
				"groupes : %s absent de la machine, appartenance de %s non posée", g, username))
		default:
			effectifs = append(effectifs, g)
		}
	}

	poses[username] = effectifs
	if len(effectifs) == 0 {
		// Une entrée vide et une entrée absente se lisent pareil, mais l'entrée
		// vide dit « on a regardé, il n'y a rien ». On la garde : c'est ce qui
		// distingue un compte sans groupe d'un compte jamais vu.
		poses[username] = []string{}
	}

	if err := ecrireGroupesPoses(poses); err != nil {
		// Les appartenances sont posées, seule leur mémoire manque. Le dire, sans
		// annuler : le prochain passage ne saura pas retirer ces groupes-là, ce
		// qui est moins grave que de laisser l'utilisateur sans ses droits.
		logs.Write_log("ERROR", "groupes : état non enregistré : "+err.Error())
	}
	return effectifs, nil
}

// retirerDuGroupe ôte un utilisateur de la liste d'un groupe de /etc/group.
//
// Le fichier est réécrit en entier : c'est un fichier de quelques kilo-octets, et
// une réécriture complète évite d'avoir à raisonner sur les décalages.
func retirerDuGroupe(groupName, username string) error {
	contenu, err := os.ReadFile(groupPath())
	if err != nil {
		return err
	}

	lignes := strings.Split(string(contenu), "\n")
	modifie := false

	for i, ligne := range lignes {
		if !strings.HasPrefix(ligne, groupName+":") {
			continue
		}
		champs := strings.Split(ligne, ":")
		if len(champs) < 4 {
			// Ligne malformée : ne pas y toucher. La réécrire « proprement »
			// inventerait des champs qu'on n'a pas lus.
			break
		}
		membres := decouper(champs[3])
		var restants []string
		for _, m := range membres {
			if m != username {
				restants = append(restants, m)
			}
		}
		if len(restants) == len(membres) {
			break // il n'y était pas
		}
		champs[3] = strings.Join(restants, ",")
		lignes[i] = strings.Join(champs, ":")
		modifie = true
		break
	}

	if !modifie {
		return nil
	}
	return os.WriteFile(groupPath(), []byte(strings.Join(lignes, "\n")), 0644)
}

// ecrireGroupesPoses réécrit le fichier d'état.
//
// Écriture atomique : un fichier temporaire puis un renommage. Une coupure au
// milieu d'un os.WriteFile direct laisserait un état tronqué, donc des
// appartenances que l'agent ne saurait plus retirer.
func ecrireGroupesPoses(poses map[string][]string) error {
	if err := os.MkdirAll(filepath.Dir(groupMapPath()), 0755); err != nil {
		return fmt.Errorf("création de %s : %w", filepath.Dir(groupMapPath()), err)
	}

	noms := make([]string, 0, len(poses))
	for nom := range poses {
		noms = append(noms, nom)
	}
	sort.Strings(noms)

	var b strings.Builder
	b.WriteString("# Appartenances de groupe posées par Vaultaire.\n")
	b.WriteString("# Format : utilisateur:groupe1,groupe2\n")
	b.WriteString("# L'agent ne retire QUE ce qui figure ici : les appartenances\n")
	b.WriteString("# posées par l'administrateur local ne sont jamais touchées.\n")
	for _, nom := range noms {
		b.WriteString(nom + ":" + strings.Join(poses[nom], ",") + "\n")
	}

	tmp := groupMapPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, groupMapPath())
}

// normaliser trie, déduplique et écarte les noms vides ou dangereux.
//
// Un nom de groupe contenant « : » ou « , » corromprait /etc/group et le fichier
// d'état : les deux sont des formats à séparateurs, et une valeur qui en contient
// déplace toutes les colonnes suivantes.
func normaliser(groupes []string) []string {
	vus := map[string]bool{}
	var out []string
	for _, g := range groupes {
		g = strings.TrimSpace(g)
		if g == "" || vus[g] {
			continue
		}
		if strings.ContainsAny(g, ":,\n\r \t") {
			logs.Write_log("WARNING", fmt.Sprintf(
				"groupes : nom %q écarté — il contient un séparateur de /etc/group", g))
			continue
		}
		vus[g] = true
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

func decouper(liste string) []string {
	var out []string
	for _, s := range strings.Split(liste, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func contient(liste []string, v string) bool {
	for _, s := range liste {
		if s == v {
			return true
		}
	}
	return false
}
