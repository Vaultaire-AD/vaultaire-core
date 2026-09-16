package localusermanagement

import (
	"bufio"
	"duckynetworkclient/V1/duckynetwork/logs"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProvisionVaultaireUser : La fonction maîtresse (Brute Force + UID Dynamique)
func ProvisionVaultaireUser(username string, isAdmin bool, pubKeys string) error {
	const startUID = 5000
	var uid int

	// 1. VÉRIFICATION : Est-ce que l'user est DÉJÀ dans /etc/passwd ?
	exists := false
	file, _ := os.Open("/etc/passwd")
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if parts[0] == username {
			exists = true
			uid, _ = strconv.Atoi(parts[2]) // On récupère son UID actuel
			break
		}
	}
	file.Close()

	// 2. CRÉATION : Si l'user n'existe pas, on l'injecte
	if !exists {
		// L'UID vient de la CARTE, pas d'un scan de /etc/passwd.
		//
		// Deux raisons de passer par elle :
		//
		//   - le module NSS lit cette carte pour répondre à getpwnam AVANT la
		//     première connexion. Attribuer ici un UID qu'elle ignore ferait
		//     diverger les deux sources, et l'utilisateur changerait d'identité
		//     selon qui le résout ;
		//
		//   - EnsureUIDMapping est idempotente et sérialisée. getNextAvailableUID
		//     relisait /etc/passwd sans verrou : deux provisionnements simultanés
		//     y trouvaient le même trou et attribuaient le même UID — le défaut
		//     même que cette correction supprime.
		entry, errMap := EnsureUIDMapping(username)
		if errMap != nil {
			return fmt.Errorf("attribution d'UID impossible pour %s : %v", username, errMap)
		}
		uid = entry.UID
		logs.Write_log("INFO", fmt.Sprintf("Création brute de %s avec UID %d", username, uid))

		homeDir := "/home/" + username

		// Ligne Passwd (User)
		passwdLine := fmt.Sprintf("%s:x:%d:%d:%s@vaultaire:%s:/bin/bash\n", username, uid, uid, username, homeDir)
		// Ligne Group (Groupe primaire du même nom)
		groupLine := fmt.Sprintf("%s:x:%d:\n", username, uid)
		// Ligne Shadow (Indispensable pour que le compte ne soit pas 'expired')
		shadowLine := fmt.Sprintf("%s:!!:19700:0:99999:7:::\n", username)

		// Injection physique dans les fichiers
		if err := appendToFile("/etc/passwd", passwdLine); err != nil {
			return err
		}
		if err := appendToFile(groupPath(), groupLine); err != nil {
			return err
		}
		if err := appendToFile("/etc/shadow", shadowLine); err != nil {
			return err
		}

		// Création du Home Directory
		os.MkdirAll(homeDir, 0700)
		copySkelFiles(homeDir, uid)
		chownRecursive(homeDir, uid, uid)
		os.Chown(homeDir, uid, uid)
	}

	// 3. CLÉS SSH : le fichier est RÉÉCRIT, pas complété.
	//
	// L'ensemble posé ici est exactement celui que le serveur vient de rendre.
	// Une clé révoquée côté annuaire disparaît donc de la machine dès la
	// connexion suivante — y compris quand il n'en reste aucune, cas où le
	// fichier devient vide.
	//
	// Le détail de l'écriture (liens symboliques, droits à la création,
	// remplacement atomique) est dans EcrireClesAutorisees. Ce qui tenait ici en
	// un os.WriteFile suivait les liens et écrivait en place, alors que le module
	// PAM se protégeait déjà des deux : deux chemins pour un même fichier, dont
	// un seul était sûr.
	home := filepath.Join("/home", username)
	if err := EcrireClesAutorisees(home, uid, uid, DecouperCles(pubKeys)); err != nil {
		return fmt.Errorf("erreur écriture authorized_keys: %v", err)
	}

	// Contexte SELinux, APRÈS l'écriture et le chown.
	//
	// Les fichiers créés ci-dessus héritent du contexte de /home, soit
	// home_root_t, au lieu de user_home_dir_t puis ssh_home_t. sshd refuse alors
	// de lire authorized_keys, et la connexion échoue par clé publique alors que
	// tout le reste a fonctionné.
	//
	// Relevé sur une machine réelle :
	//   denied { open } path="/home/<user>/.ssh/authorized_keys"
	//   tcontext=system_u:object_r:home_root_t
	RestaurerContexteSELinux(home)

	// 4. SUDO : Gestion du groupe wheel/sudo
	if isAdmin {
		logs.Write_log("INFO", "Ajout de "+username+" au groupe wheel")
		// L'échec est dit, pas fatal : le compte est créé et ses clés posées.
		// Refuser la session parce que le groupe d'administration manque
		// laisserait l'utilisateur dehors, alors qu'il lui reste un accès valide
		// — sans les droits sudo, ce que le journal permet de diagnostiquer.
		switch pose, err := addUserToGroupManual("wheel", username); {
		case err != nil:
			logs.Write_log("WARNING", fmt.Sprintf(
				"Ajout de %s au groupe wheel impossible : %v", username, err))
		case !pose:
			logs.Write_log("WARNING", fmt.Sprintf(
				"Groupe wheel absent de cette machine : %s n'aura pas les droits "+
					"d'administration", username))
		}
	}

	return nil
}

// --- FONCTIONS OUTILS (Helpers) ---

// copySkelFiles imite le comportement de useradd en copiant /etc/skel
func copySkelFiles(homeDir string, uid int) {
	skelPath := "/etc/skel"
	entries, err := os.ReadDir(skelPath)
	if err != nil {
		logs.Write_log("ERROR", "Impossible de lire /etc/skel: "+err.Error())
		return
	}

	for _, entry := range entries {
		src := filepath.Join(skelPath, entry.Name())
		dst := filepath.Join(homeDir, entry.Name())

		// On lit le fichier source
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}

		// On l'écrit dans le home de l'user
		os.WriteFile(dst, data, 0644)
	}
}

// chownRecursive s'assure que l'user possède bien tout son home
func chownRecursive(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			err = os.Chown(name, uid, gid)
		}
		return err
	})
}

// getNextAvailableUID a été RETIRÉE.
//
// Elle scannait /etc/passwd sans verrou pour trouver un trou. Deux
// provisionnements simultanés y trouvaient le même, et attribuaient le même
// UID à deux utilisateurs différents — exactement le défaut que la carte
// corrige, réintroduit par une autre porte.
//
// L'attribution passe désormais par EnsureUIDMapping (uidmap.go), qui est
// sérialisée et tient compte à la fois de la carte et de /etc/passwd.

// Ajoute une ligne à la fin d'un fichier (ex: /etc/passwd)
func appendToFile(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

// Ajoute un utilisateur à la liste d'un groupe (ex: wheel)
// addUserToGroupManual inscrit un utilisateur dans un groupe existant.
//
// Ne crée aucun groupe : un groupe absent est ignoré, et la fonction le dit par
// son booléen de retour. Voir groupes_utilisateur.go pour la raison.
//
// # L'appartenance se lit champ par champ
//
// La version précédente testait `strings.Contains(line, username)`, ce qui
// confondait l'appartenance avec la simple présence des lettres dans la ligne.
// Un utilisateur « bob » était considéré comme déjà membre d'un groupe nommé
// « bobs », ou dès qu'un « bobby » y figurait : l'inscription n'avait pas lieu,
// sans erreur, et les droits manquaient sans que rien ne l'indique. Le nom du
// groupe lui-même ouvre la ligne, donc un compte homonyme de son groupe primaire
// tombait systématiquement dans le piège — or c'est précisément ce que
// ProvisionVaultaireUser crée pour chaque compte.
func addUserToGroupManual(groupName, username string) (bool, error) {
	content, err := os.ReadFile(groupPath())
	if err != nil {
		return false, err
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, groupName+":") {
			continue
		}
		champs := strings.Split(line, ":")
		if len(champs) < 4 {
			// Ligne malformée : ne pas y toucher. La compléter inventerait des
			// champs qu'on n'a pas lus.
			return false, fmt.Errorf("ligne de groupe %q malformée", groupName)
		}
		for _, m := range decouper(champs[3]) {
			if m == username {
				return true, nil // déjà membre
			}
		}
		if strings.TrimSpace(champs[3]) == "" {
			champs[3] = username
		} else {
			champs[3] = champs[3] + "," + username
		}
		lines[i] = strings.Join(champs, ":")
		if err := os.WriteFile(groupPath(), []byte(strings.Join(lines, "\n")), 0644); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil // le groupe n'existe pas sur cette machine
}
