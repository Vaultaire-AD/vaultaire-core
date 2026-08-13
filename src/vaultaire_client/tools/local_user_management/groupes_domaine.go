package localusermanagement

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Les groupes du domaine, posés sur la machine.
//
// # Le problème
//
// L'agent posait les appartenances annoncées dans 03_02, mais ne créait aucun
// groupe : un groupe du domaine absent de la machine était simplement ignoré.
// La plupart des appartenances restaient donc sans effet.
//
// Créer le groupe au vol aurait été pire que de ne rien faire. Le GID aurait été
// choisi localement, donc DIFFÉRENT sur chaque machine — et sur un partage NFS,
// où seuls des nombres circulent, deux postes du même domaine auraient lu des
// droits différents sur les mêmes fichiers. Le numéro vient donc du serveur, par
// une règle sans état (voir gid_domaine.go).
//
// # Ce que l'agent ne touche pas
//
// Les groupes qu'il n'a pas créés. Comme pour les appartenances, la limite est
// tenue par un fichier d'état — `/etc/vaultaire/groups.map`. Un groupe local
// homonyme d'un groupe du domaine n'est jamais repris : il est signalé et laissé
// intact, GID compris. Le renuméroter changerait le propriétaire de tous les
// fichiers qui en portent la marque.
//
// # La suppression VIDE, elle n'efface pas
//
// Un groupe disparu du domaine perd ses membres ; sa ligne reste.
//
// Effacer la ligne rendrait orphelins tous les fichiers dont c'est le groupe
// propriétaire : `ls -l` n'afficherait plus qu'un nombre, et les droits de groupe
// deviendraient impossibles à interpréter — sur des données que personne n'a
// demandé à toucher, et sans qu'aucune trace n'explique d'où vient le numéro. Un
// agent ne peut pas savoir ce qui est marqué de ce groupe sans parcourir tous les
// systèmes de fichiers montés.
//
// Vider suffit à couper les droits, immédiatement et partout. Le nom subsiste
// pour que l'administrateur puisse lire ce qu'il regarde. L'effacement définitif
// est une décision humaine : `vlt purge groups`.

func groupsMapPath() string { return filepath.Join(repertoireEtat, "groups.map") }

// groupsMapMu sérialise les écritures de la carte des groupes.
//
// Distincte de groupMapMu, qui protège les APPARTENANCES : les deux fichiers
// sont écrits par des chemins différents — une synchronisation périodique d'un
// côté, une ouverture de session de l'autre — et un verrou commun ferait attendre
// une connexion utilisateur derrière un cycle de synchronisation.
var groupsMapMu sync.Mutex

// GroupeDomaine est un groupe annoncé par le serveur.
type GroupeDomaine struct {
	Nom     string
	IDGroup int
}

// GID rend le numéro de ce groupe, ou une erreur si l'identifiant est hors borne.
func (g GroupeDomaine) GID() (int, error) { return GIDDeGroupe(g.IDGroup) }

// AnalyserLigneGroupe lit une ligne « <nom>:<id_group> » de la trame 03_09.
//
// # Pourquoi l'agent revalide
//
// Le serveur valide déjà à l'émission. Il est authentifié — il n'est pas
// infaillible. Une injection SQL sur la table `groups`, une base restaurée de
// travers, un bogue : le contenu de la trame n'est pas plus sûr que la base d'où
// il sort, et ce qui est en jeu ici est une écriture dans `/etc/group`.
//
// Un nom contenant « : » ou « , » y décalerait toutes les colonnes ; un
// identifiant hors borne produirait un GID hors de la plage réservée, jusqu'à 0
// qui est `root`.
func AnalyserLigneGroupe(ligne string) (GroupeDomaine, error) {
	ligne = strings.TrimSpace(ligne)
	if ligne == "" {
		return GroupeDomaine{}, fmt.Errorf("ligne vide")
	}

	nom, idTexte, ok := strings.Cut(ligne, ":")
	if !ok {
		return GroupeDomaine{}, fmt.Errorf("ligne %q : séparateur absent", ligne)
	}
	nom = strings.TrimSpace(nom)
	if nom == "" {
		return GroupeDomaine{}, fmt.Errorf("ligne %q : nom vide", ligne)
	}
	if strings.ContainsAny(nom, ":,\n\r \t") {
		return GroupeDomaine{}, fmt.Errorf("nom %q : contient un séparateur de /etc/group", nom)
	}

	id, err := strconv.Atoi(strings.TrimSpace(idTexte))
	if err != nil {
		return GroupeDomaine{}, fmt.Errorf("ligne %q : identifiant illisible", ligne)
	}
	if _, err := GIDDeGroupe(id); err != nil {
		return GroupeDomaine{}, fmt.Errorf("groupe %q : %w", nom, err)
	}
	return GroupeDomaine{Nom: nom, IDGroup: id}, nil
}

// ChargerGroupesCrees lit la carte des groupes créés par l'agent.
//
// Format « <nom>:<gid> ». Une carte absente n'est pas une erreur : c'est l'état
// d'une machine qui n'a encore rien créé.
func ChargerGroupesCrees() (map[string]int, error) {
	crees := map[string]int{}

	f, err := os.Open(groupsMapPath())
	if err != nil {
		if os.IsNotExist(err) {
			return crees, nil
		}
		return crees, fmt.Errorf("lecture de %s : %w", groupsMapPath(), err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ligne := strings.TrimSpace(scanner.Text())
		if ligne == "" || strings.HasPrefix(ligne, "#") {
			continue
		}
		nom, gidTexte, ok := strings.Cut(ligne, ":")
		if !ok || nom == "" {
			continue
		}
		gid, err := strconv.Atoi(strings.TrimSpace(gidTexte))
		if err != nil {
			continue
		}
		crees[nom] = gid
	}
	if err := scanner.Err(); err != nil {
		return crees, fmt.Errorf("parcours de %s : %w", groupsMapPath(), err)
	}
	return crees, nil
}

// ResultatSynchro rend compte d'un passage.
type ResultatSynchro struct {
	Crees   []string // groupes ajoutés à /etc/group
	Vides   []string // groupes disparus du domaine, membres retirés
	Ignores []string // homonymes locaux, non repris
}

// SynchroniserGroupesDomaine aligne /etc/group sur la liste annoncée.
//
// # L'ordre : créations d'abord, vidages ensuite
//
// L'inverse de l'ordre retenu pour les appartenances, et pour la même raison de
// fond. Ici, vider d'abord ouvrirait une fenêtre pendant laquelle un groupe
// renommé — disparu sous un nom, réapparu sous un autre — n'existerait sous
// aucun des deux. Créer d'abord ne retire jamais de droit par accident : le
// vidage qui suit s'en charge, sur une liste déjà à jour.
func SynchroniserGroupesDomaine(annonces []GroupeDomaine) (ResultatSynchro, error) {
	var res ResultatSynchro

	groupsMapMu.Lock()
	defer groupsMapMu.Unlock()

	crees, err := ChargerGroupesCrees()
	if err != nil {
		// État illisible : on CRÉE, on ne VIDE pas. Vider sans savoir ce qu'on a
		// créé reviendrait à retirer les membres d'un groupe posé par
		// l'administrateur local — le fichier existe pour l'empêcher.
		logs.Write_log("WARNING",
			"groupes du domaine : état illisible ("+err.Error()+"), aucun vidage effectué")
		crees = map[string]int{}
	}

	voulus := map[string]bool{}

	// CRÉATIONS.
	for _, g := range annonces {
		gid, err := g.GID()
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("groupes du domaine : %v", err))
			continue
		}
		voulus[g.Nom] = true

		gidLocal, existe, err := gidDuGroupe(g.Nom)
		if err != nil {
			logs.Write_log("ERROR", "groupes du domaine : "+err.Error())
			continue
		}

		switch {
		case !existe:
			if err := creerGroupe(g.Nom, gid); err != nil {
				logs.Write_log("ERROR", fmt.Sprintf(
					"groupes du domaine : création de %s (GID %d) impossible : %v",
					g.Nom, gid, err))
				continue
			}
			crees[g.Nom] = gid
			res.Crees = append(res.Crees, g.Nom)
			logs.Write_log("INFO", fmt.Sprintf(
				"groupes du domaine : %s créé avec le GID %d", g.Nom, gid))

		case gidLocal == gid:
			// Déjà en place et au bon numéro. Il est noté comme géré : une
			// machine dont la carte a été perdue retrouve ainsi ses groupes sans
			// les recréer, et sans les abandonner à jamais.
			crees[g.Nom] = gid

		default:
			// Le groupe existe avec un AUTRE numéro. Jamais renuméroté : le GID
			// est écrit dans les inodes de tous les fichiers qui en portent la
			// marque, et le changer les donnerait d'un coup à un autre groupe.
			//
			// Le cas normal ne passe PAS par ici — un groupe déjà au bon numéro
			// est traité au-dessus. Cette branche signale toujours une anomalie,
			// et l'avertissement est donc répété à chaque cycle plutôt que dit
			// une fois : tant que l'écart dure, la machine diverge du parc.
			res.Ignores = append(res.Ignores, g.Nom)
			if _, connu := crees[g.Nom]; connu {
				logs.Write_log("WARNING", fmt.Sprintf(
					"groupes du domaine : le GID de %s est passé à %d alors que "+
						"Vaultaire l'avait créé à %d — laissé intact, mais cette "+
						"machine ne partage plus ce groupe avec le reste du parc",
					g.Nom, gidLocal, gid))
			} else {
				logs.Write_log("WARNING", fmt.Sprintf(
					"groupes du domaine : %s existe déjà localement avec le GID %d "+
						"au lieu de %d — laissé intact, les appartenances posées "+
						"dedans ne vaudront que sur cette machine",
					g.Nom, gidLocal, gid))
			}
		}
	}

	// VIDAGES : ce que l'agent avait créé et que le domaine n'annonce plus.
	for nom := range crees {
		if voulus[nom] {
			continue
		}
		if err := viderGroupe(nom); err != nil {
			logs.Write_log("ERROR", fmt.Sprintf(
				"groupes du domaine : vidage de %s impossible : %v", nom, err))
			continue
		}
		res.Vides = append(res.Vides, nom)
		logs.Write_log("INFO", fmt.Sprintf(
			"groupes du domaine : %s a disparu du domaine, ses membres sont retirés "+
				"(la ligne est conservée — voir « vlt purge groups »)", nom))
	}

	sort.Strings(res.Crees)
	sort.Strings(res.Vides)
	sort.Strings(res.Ignores)

	if err := ecrireGroupesCrees(crees); err != nil {
		// Les groupes sont posés, seule leur mémoire manque. Le prochain passage
		// ne saura pas les vider — moins grave que de perdre les groupes eux-mêmes.
		logs.Write_log("ERROR", "groupes du domaine : état non enregistré : "+err.Error())
	}
	return res, nil
}

// lireGroupes rend le contenu de /etc/group, avec l'erreur déjà située.
//
// Le chemin passe par groupPath() et non par une constante : c'est ce qui permet
// aux tests du paquet de travailler sur un fichier temporaire, au lieu d'écrire
// dans le /etc/group de la machine qui les exécute.
func lireGroupes() (string, error) {
	contenu, err := os.ReadFile(groupPath())
	if err != nil {
		return "", fmt.Errorf("lecture de %s : %w", groupPath(), err)
	}
	return string(contenu), nil
}

// gidDuGroupe lit le GID d'un groupe dans /etc/group.
func gidDuGroupe(nom string) (gid int, existe bool, err error) {
	contenu, err := lireGroupes()
	if err != nil {
		return 0, false, err
	}
	for _, ligne := range strings.Split(contenu, "\n") {
		if !strings.HasPrefix(ligne, nom+":") {
			continue
		}
		champs := strings.Split(ligne, ":")
		if len(champs) < 4 {
			return 0, true, fmt.Errorf("ligne de groupe %q malformée", nom)
		}
		gid, err := strconv.Atoi(strings.TrimSpace(champs[2]))
		if err != nil {
			return 0, true, fmt.Errorf("groupe %q : GID illisible (%q)", nom, champs[2])
		}
		return gid, true, nil
	}
	return 0, false, nil
}

// creerGroupe ajoute une ligne à /etc/group.
//
// Écrit le fichier directement, comme le reste du paquet, plutôt que d'appeler
// `groupadd` : la commande n'existe pas partout sous le même nom, refuse les GID
// hors de sa propre plage configurée dans /etc/login.defs, et son échec ne se
// distingue pas facilement d'un groupe déjà présent.
//
// # Le GID est vérifié une dernière fois ici
//
// C'est le point d'écriture. Un contrôle en amont peut être contourné par un
// appelant futur qui construirait un GroupeDomaine à la main ; celui-ci ne le
// peut pas.
func creerGroupe(nom string, gid int) error {
	if !EstGIDDeDomaine(gid) {
		return fmt.Errorf("GID %d hors de la plage des groupes du domaine (%d-%d)",
			gid, BaseGIDDomaine+1, GIDMaxDomaine)
	}
	if nom == "" || strings.ContainsAny(nom, ":,\n\r \t") {
		return fmt.Errorf("nom de groupe %q invalide", nom)
	}

	// Un GID déjà pris par un AUTRE groupe : refuser. Deux lignes de même numéro
	// donnent aux membres de l'un les droits de l'autre, et rien ne le signale.
	contenu, err := os.ReadFile(groupPath())
	if err != nil {
		return fmt.Errorf("lecture de %s : %w", groupPath(), err)
	}
	for _, ligne := range strings.Split(string(contenu), "\n") {
		champs := strings.Split(ligne, ":")
		if len(champs) < 4 {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(champs[2])); err == nil && n == gid {
			return fmt.Errorf("GID %d déjà occupé par le groupe %q", gid, champs[0])
		}
	}

	// La nouvelle ligne est précédée d'un saut si le fichier n'en finit pas par
	// un. `appendToFile` écrit tel quel : sur un /etc/group sans retour final —
	// ce qui n'arrive pas sur un système sain, mais arrive après une écriture
	// interrompue — la ligne se collerait à la précédente, et deux groupes
	// n'en feraient plus qu'un, illisible.
	ligne := fmt.Sprintf("%s:x:%d:\n", nom, gid)
	if len(contenu) > 0 && !strings.HasSuffix(string(contenu), "\n") {
		ligne = "\n" + ligne
	}
	return appendToFile(groupPath(), ligne)
}

// viderGroupe retire tous les membres d'un groupe sans effacer sa ligne.
func viderGroupe(nom string) error {
	contenu, err := os.ReadFile(groupPath())
	if err != nil {
		return err
	}

	lignes := strings.Split(string(contenu), "\n")
	for i, ligne := range lignes {
		if !strings.HasPrefix(ligne, nom+":") {
			continue
		}
		champs := strings.Split(ligne, ":")
		if len(champs) < 4 {
			return fmt.Errorf("ligne de groupe %q malformée", nom)
		}
		if strings.TrimSpace(champs[3]) == "" {
			return nil // déjà vide
		}
		champs[3] = ""
		lignes[i] = strings.Join(champs, ":")
		return os.WriteFile(groupPath(), []byte(strings.Join(lignes, "\n")), 0644)
	}
	return nil // le groupe n'est plus là : rien à vider
}

// EffacerGroupesVides retire définitivement les lignes des groupes créés par
// l'agent qui n'ont plus aucun membre.
//
// # Pourquoi ce n'est PAS fait automatiquement
//
// Les fichiers marqués de ce groupe deviennent orphelins : `ls -l` n'affiche
// plus qu'un nombre. L'agent ne peut pas savoir ce qui en porte la marque sans
// parcourir tous les systèmes de fichiers montés — y compris les partages
// réseau, où le parcours peut durer des heures et où les fichiers appartiennent
// à d'autres machines.
//
// Le vidage coupe déjà les droits. L'effacement ne gagne que de la propreté, et
// coûte de la lisibilité : c'est une décision humaine, prise machine par machine.
//
// Rend les noms effacés.
func EffacerGroupesVides(noms []string) ([]string, error) {
	groupsMapMu.Lock()
	defer groupsMapMu.Unlock()

	crees, err := ChargerGroupesCrees()
	if err != nil {
		return nil, fmt.Errorf("état illisible : %w", err)
	}

	contenu, err := os.ReadFile(groupPath())
	if err != nil {
		return nil, fmt.Errorf("lecture de %s : %w", groupPath(), err)
	}
	lignes := strings.Split(string(contenu), "\n")

	aEffacer := map[string]bool{}
	for _, n := range noms {
		if _, gere := crees[n]; !gere {
			// Refus net plutôt que silence : demander l'effacement d'un groupe
			// que l'agent n'a pas créé est une erreur de l'opérateur, et la lui
			// taire lui ferait croire le geste fait.
			return nil, fmt.Errorf("groupe %q non créé par Vaultaire : refus d'effacer", n)
		}
		aEffacer[n] = true
	}

	var restantes []string
	var effaces []string
	for _, ligne := range lignes {
		champs := strings.Split(ligne, ":")
		if len(champs) < 4 || !aEffacer[champs[0]] {
			restantes = append(restantes, ligne)
			continue
		}
		if strings.TrimSpace(champs[3]) != "" {
			// Un groupe encore peuplé n'est pas effacé : ses membres perdraient
			// leurs droits sans que personne l'ait demandé.
			return nil, fmt.Errorf("groupe %q a encore des membres (%s) : "+
				"non effacé", champs[0], champs[3])
		}
		effaces = append(effaces, champs[0])
	}

	if len(effaces) == 0 {
		return nil, nil
	}

	if err := os.WriteFile(groupPath(), []byte(strings.Join(restantes, "\n")), 0644); err != nil {
		return nil, err
	}
	for _, n := range effaces {
		delete(crees, n)
	}
	if err := ecrireGroupesCrees(crees); err != nil {
		logs.Write_log("ERROR", "groupes du domaine : état non enregistré : "+err.Error())
	}
	sort.Strings(effaces)
	return effaces, nil
}

// ecrireGroupesCrees réécrit la carte des groupes.
//
// Écriture atomique : fichier temporaire puis renommage. Une coupure au milieu
// d'un os.WriteFile direct laisserait une carte tronquée, donc des groupes que
// l'agent ne saurait plus vider — ni distinguer de ceux de l'administrateur.
func ecrireGroupesCrees(crees map[string]int) error {
	if err := os.MkdirAll(filepath.Dir(groupsMapPath()), 0755); err != nil {
		return fmt.Errorf("création de %s : %w", filepath.Dir(groupsMapPath()), err)
	}

	noms := make([]string, 0, len(crees))
	for nom := range crees {
		noms = append(noms, nom)
	}
	sort.Strings(noms)

	var b strings.Builder
	b.WriteString("# Groupes du domaine poses par Vaultaire.\n")
	b.WriteString("# Format : groupe:gid\n")
	b.WriteString("# L'agent ne vide QUE ce qui figure ici : les groupes crees par\n")
	b.WriteString("# l'administrateur local ne sont jamais touches.\n")
	for _, nom := range noms {
		b.WriteString(nom + ":" + strconv.Itoa(crees[nom]) + "\n")
	}

	tmp := groupsMapPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, groupsMapPath())
}
