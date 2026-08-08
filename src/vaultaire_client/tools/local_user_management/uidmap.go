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

	"vaultaire_client/logs"
)

// Carte des identifiants d'utilisateurs du domaine.
//
// # À quoi elle sert
//
// Le module NSS (`libnss_vaultaire`) doit pouvoir répondre à `getpwnam` AVANT
// la première connexion d'un utilisateur : sshd exige une entrée passwd avant
// même de lancer l'authentification, et refuse un compte inconnu quoi qu'il
// arrive ensuite.
//
// Il lui faut donc une source. Cette carte est cette source.
//
// # Pourquoi un fichier, et pas le socket
//
// Un module NSS est chargé dans TOUS les processus de la machine, y compris
// ceux sans aucun privilège. Le faire dialoguer avec l'agent aurait trois
// défauts : une latence sur chaque résolution de nom, un blocage de tout le
// système si l'agent ne répond plus, et un risque de récursion si l'agent
// lui-même résout un nom.
//
// Un fichier se lit sans dépendance, sans privilège et sans attente.
//
// # Ce que la carte remplace
//
// Le module NSS attribuait auparavant le même UID (5001) à tout nom contenant
// un « @ ». Sous Unix l'UID est l'identité : les utilisateurs du domaine
// étaient tous le même compte pour le noyau, sans aucune séparation entre eux.
const (
	// UIDMapDir et UIDMapPath : lisibles par tous, écrivables par root seul.
	//
	// 0644 n'est pas un relâchement : NSS est chargé dans des processus non
	// privilégiés, qui doivent pouvoir lire. C'est exactement le régime de
	// /etc/passwd, et le contenu est de même nature — des noms et des numéros,
	// aucun secret.
	UIDMapDir  = "/etc/vaultaire"
	UIDMapPath = UIDMapDir + "/uid.map"

	// Plage réservée. Le module NSS applique les mêmes bornes en lecture et
	// refuse tout ce qui en sort — c'est ce qui empêche une carte trafiquée
	// d'attribuer l'UID 0.
	UIDMin = 5000
	UIDMax = 60000
)

// uidMapMu sérialise les écritures.
//
// L'agent provisionne depuis plusieurs goroutines — une session PAM, un cycle
// GPO, une révocation. Deux écritures concurrentes attribueraient le même UID
// à deux utilisateurs, ce qui est précisément le défaut que la carte corrige.
var uidMapMu sync.Mutex

// UIDEntry est une ligne de la carte.
type UIDEntry struct {
	Username string
	UID      int
	GID      int
}

// LoadUIDMap lit la carte.
//
// Une carte absente n'est pas une erreur : c'est l'état d'une machine qui
// n'a pas encore provisionné d'utilisateur.
//
// Les lignes malformées ou hors plage sont ignorées plutôt que fatales. La
// carte est un fichier sur disque ; une ligne abîmée ne doit pas faire perdre
// les autres, ni empêcher l'agent de fonctionner.
func LoadUIDMap() (map[string]UIDEntry, error) {
	entries := map[string]UIDEntry{}

	f, err := os.Open(mapPath())
	if err != nil {
		if os.IsNotExist(err) {
			return entries, nil
		}
		return entries, fmt.Errorf("lecture de %s : %w", mapPath(), err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ligne := strings.TrimSpace(scanner.Text())
		if ligne == "" || strings.HasPrefix(ligne, "#") {
			continue
		}
		parts := strings.Split(ligne, ":")
		if len(parts) != 3 {
			continue
		}
		nom := parts[0]
		uid, errU := strconv.Atoi(parts[1])
		gid, errG := strconv.Atoi(parts[2])
		if nom == "" || errU != nil || errG != nil {
			continue
		}
		if !uidDansLaPlage(uid) || !uidDansLaPlage(gid) {
			logs.Write_log("WARNING", fmt.Sprintf(
				"uid.map : entrée %q hors plage (uid=%d) ignorée", nom, uid))
			continue
		}
		entries[nom] = UIDEntry{Username: nom, UID: uid, GID: gid}
	}
	if err := scanner.Err(); err != nil {
		return entries, fmt.Errorf("parcours de %s : %w", mapPath(), err)
	}

	return entries, nil
}

// EnsureUIDMapping garantit qu'un utilisateur a une entrée, et la retourne.
//
// Idempotente : rappelée pour un utilisateur déjà connu, elle rend l'UID
// existant sans rien réécrire. C'est ce qui rend l'identité STABLE — un UID qui
// changerait entre deux connexions laisserait derrière lui des fichiers
// appartenant à un numéro que plus personne ne porte.
func EnsureUIDMapping(username string) (UIDEntry, error) {
	uidMapMu.Lock()
	defer uidMapMu.Unlock()

	entries, err := LoadUIDMap()
	if err != nil {
		// On continue malgré l'erreur de lecture : refuser d'attribuer bloquerait
		// toute connexion. Mais on le dit fort — repartir d'une carte vide
		// réattribuerait des UID déjà utilisés.
		logs.Write_log("CRITICAL", "uid.map illisible, attribution sur base partielle : "+err.Error())
	}

	if e, ok := entries[username]; ok {
		return e, nil
	}

	// Le compte existe-t-il DÉJÀ localement ?
	//
	// Si oui, on adopte son UID au lieu d'en inventer un nouveau. Sans ce
	// contrôle, un compte provisionné avant l'existence de la carte se voyait
	// attribuer un second numéro : /etc/passwd disait 5000, la carte 5001.
	//
	// La divergence est silencieuse — « files » venant en premier dans
	// nsswitch.conf, c'est l'UID de /etc/passwd qui fait autorité et tout
	// fonctionne. Mais la carte ment, et elle ment sur la seule chose qu'elle
	// est censée savoir. Le jour où le compte local est purgé puis recréé, ou
	// bien l'ordre de nsswitch.conf modifié, l'utilisateur change d'identité et
	// perd ses fichiers.
	if uid, gid, trouve := uidDuCompteLocal(username); trouve {
		entry := UIDEntry{Username: username, UID: uid, GID: gid}
		entries[username] = entry
		if err := writeUIDMap(entries); err != nil {
			return UIDEntry{}, err
		}
		logs.Write_log("INFO", fmt.Sprintf(
			"uid.map : %s adopte l'UID %d de son compte local existant", username, uid))
		return entry, nil
	}

	uid, err := prochainUIDLibre(entries)
	if err != nil {
		return UIDEntry{}, err
	}

	entry := UIDEntry{Username: username, UID: uid, GID: uid}
	entries[username] = entry

	if err := writeUIDMap(entries); err != nil {
		return UIDEntry{}, err
	}

	logs.Write_log("INFO", fmt.Sprintf(
		"uid.map : %s reçoit l'UID %d", username, uid))
	return entry, nil
}

// RemoveUIDMapping retire un utilisateur de la carte.
//
// À n'appeler que quand le compte local est réellement supprimé. Retirer
// l'entrée alors que des fichiers lui appartiennent encore les rendrait
// orphelins, et l'UID pourrait être réattribué à quelqu'un d'autre — qui
// hériterait de ces fichiers.
func RemoveUIDMapping(username string) error {
	uidMapMu.Lock()
	defer uidMapMu.Unlock()

	entries, err := LoadUIDMap()
	if err != nil {
		return err
	}
	if _, ok := entries[username]; !ok {
		return nil
	}
	delete(entries, username)
	return writeUIDMap(entries)
}

// prochainUIDLibre choisit un UID non utilisé.
//
// Il évite à la fois ceux de la carte et ceux de /etc/passwd : un UID déjà
// porté par un compte local ferait de l'utilisateur du domaine son homonyme
// exact aux yeux du noyau.
func prochainUIDLibre(entries map[string]UIDEntry) (int, error) {
	pris := map[int]bool{}
	for _, e := range entries {
		pris[e.UID] = true
	}
	for _, uid := range uidsDeEtcPasswd() {
		pris[uid] = true
	}

	for uid := UIDMin; uid <= UIDMax; uid++ {
		if !pris[uid] {
			return uid, nil
		}
	}
	return 0, fmt.Errorf("plage d'UID %d-%d épuisée", UIDMin, UIDMax)
}

// uidDuCompteLocal cherche un compte de ce nom dans /etc/passwd.
//
// C'est /etc/passwd qui fait autorité : « files » vient en premier dans
// nsswitch.conf, et l'UID qui y figure est celui que le noyau applique
// réellement aux fichiers. La carte doit s'y conformer, jamais l'inverse.
func uidDuCompteLocal(username string) (int, int, bool) {
	f, err := os.Open(passwdPath())
	if err != nil {
		return 0, 0, false
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 4 || parts[0] != username {
			continue
		}
		uid, errU := strconv.Atoi(parts[2])
		gid, errG := strconv.Atoi(parts[3])
		if errU != nil || errG != nil {
			return 0, 0, false
		}
		// Hors plage : on n'adopte pas. Un compte du domaine qui porterait
		// l'UID 0 ou celui d'un service système ne doit pas voir cette valeur
		// entrer dans la carte, que le module NSS refuserait de toute façon.
		if !uidDansLaPlage(uid) || !uidDansLaPlage(gid) {
			return 0, 0, false
		}
		return uid, gid, true
	}
	return 0, 0, false
}

// uidsDeEtcPasswd relève les UID déjà attribués localement.
//
// Un échec de lecture rend une liste vide plutôt qu'une erreur : mieux vaut
// risquer une collision — rattrapée par useradd, qui refusera — que de bloquer
// toute connexion parce que /etc/passwd est momentanément illisible.
func uidsDeEtcPasswd() []int {
	f, err := os.Open(passwdPath())
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var out []int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 3 {
			continue
		}
		if uid, err := strconv.Atoi(parts[2]); err == nil {
			out = append(out, uid)
		}
	}
	return out
}

// writeUIDMap réécrit la carte de façon atomique.
//
// Temporaire puis rename : le module NSS lit ce fichier depuis n'importe quel
// processus, à n'importe quel moment. Une écriture en place le laisserait
// tronqué le temps de l'opération, et toute résolution tombant dans cette
// fenêtre échouerait — donc une connexion refusée sans raison visible.
func writeUIDMap(entries map[string]UIDEntry) error {
	if err := os.MkdirAll(mapDir(), 0o755); err != nil {
		return fmt.Errorf("création de %s : %w", mapDir(), err)
	}

	// Tri par UID : la carte est un fichier qu'un administrateur lira. L'ordre
	// d'itération d'une map le rendrait différent à chaque écriture, et donc
	// illisible en diff.
	liste := make([]UIDEntry, 0, len(entries))
	for _, e := range entries {
		liste = append(liste, e)
	}
	sort.Slice(liste, func(i, j int) bool { return liste[i].UID < liste[j].UID })

	var b strings.Builder
	b.WriteString("# Carte des identifiants des utilisateurs du domaine.\n")
	b.WriteString("# Écrite par l'agent Vaultaire, lue par libnss_vaultaire.\n")
	b.WriteString("# Format : nom:uid:gid — NE PAS ÉDITER À LA MAIN.\n")
	for _, e := range liste {
		b.WriteString(fmt.Sprintf("%s:%d:%d\n", e.Username, e.UID, e.GID))
	}

	tmp, err := os.CreateTemp(mapDir(), ".uid.map.*")
	if err != nil {
		return fmt.Errorf("fichier temporaire : %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("écriture de la carte : %w", err)
	}
	// Sync avant rename : sans cela, une coupure juste après le rename peut
	// laisser un fichier de taille correcte mais au contenu vide — et une carte
	// vide fait perdre toutes les identités d'un coup.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("synchronisation : %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fermeture du temporaire : %w", err)
	}
	// Le mode est posé AVANT la publication : le fichier n'existe jamais sous
	// son nom définitif avec les droits restreints de CreateTemp (0600), qui
	// empêcheraient NSS de le lire depuis un processus non privilégié.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("mode de la carte : %w", err)
	}
	if err := os.Rename(tmpName, mapPath()); err != nil {
		return fmt.Errorf("publication de la carte : %w", err)
	}

	return nil
}

func uidDansLaPlage(id int) bool { return id >= UIDMin && id <= UIDMax }

// Résolution des chemins.
//
// Les valeurs de production sont des constantes, pour que personne ne les
// déplace par inadvertance. Les tests, eux, ne peuvent pas écrire dans /etc :
// VAULTAIRE_UID_MAP_DIR leur donne un répertoire à eux.
//
// La variable est lue à CHAQUE appel et non mémorisée dans un init() : un test
// qui la pose après le chargement du paquet doit être pris en compte, sinon le
// mécanisme ne sert qu'au premier test du fichier.
func mapDir() string {
	if d := os.Getenv("VAULTAIRE_UID_MAP_DIR"); d != "" {
		return d
	}
	return UIDMapDir
}

func mapPath() string { return filepath.Join(mapDir(), "uid.map") }

// passwdPath : même mécanisme que pour la carte.
//
// Sans lui, le test qui vérifie l'adoption de l'UID d'un compte local dépendrait
// du /etc/passwd de la machine qui exécute les tests — il passerait ici, serait
// sauté là, et ne mesurerait rien de fiable nulle part.
func passwdPath() string {
	if p := os.Getenv("VAULTAIRE_PASSWD_FILE"); p != "" {
		return p
	}
	return "/etc/passwd"
}
