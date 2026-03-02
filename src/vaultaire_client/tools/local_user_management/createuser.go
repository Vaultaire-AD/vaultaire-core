package localusermanagement

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"vaultaire_client/logs"
)

// ProvisionVaultaireUser : La fonction maîtresse (Brute Force + UID Dynamique)
func ProvisionVaultaireUser(username string, isAdmin bool, pubKeys string) error {
	const startUID = 5000
	var uid int
	var err error

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
		// Trouver le prochain UID libre (ex: 5000, 5001, ...)
		uid = getNextAvailableUID(startUID)
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
		if err := appendToFile("/etc/group", groupLine); err != nil {
			return err
		}
		if err := appendToFile("/etc/shadow", shadowLine); err != nil {
			return err
		}

		// Création du Home Directory
		os.MkdirAll(homeDir, 0700)
		os.Chown(homeDir, uid, uid)
	}

	// 3. CLÉS SSH : On les pose dans le home (qu'il soit nouveau ou ancien)
	sshDir := filepath.Join("/home/", username, ".ssh")
	os.MkdirAll(sshDir, 0700)
	os.Chown(sshDir, uid, uid)

	authFile := filepath.Join(sshDir, "authorized_keys")
	err = os.WriteFile(authFile, []byte(pubKeys+"\n"), 0600)
	if err != nil {
		return fmt.Errorf("erreur écriture authorized_keys: %v", err)
	}
	os.Chown(authFile, uid, uid)

	// 4. SUDO : Gestion du groupe wheel/sudo
	if isAdmin {
		logs.Write_log("INFO", "Ajout de "+username+" au groupe wheel")
		addUserToGroupManual("wheel", username)
	}

	return nil
}

// --- FONCTIONS OUTILS (Helpers) ---

// Trouve le prochain UID disponible en scannant /etc/passwd
func getNextAvailableUID(start int) int {
	max := start
	f, _ := os.Open("/etc/passwd")
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		p := strings.Split(s.Text(), ":")
		if len(p) > 2 {
			id, _ := strconv.Atoi(p[2])
			if id >= max && id < 6000 { // On reste dans la plage 5000-6000
				max = id + 1
			}
		}
	}
	return max
}

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
func addUserToGroupManual(groupName, username string) {
	path := "/etc/group"
	content, _ := os.ReadFile(path)
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, groupName+":") {
			if !strings.Contains(line, username) {
				if strings.HasSuffix(line, ":") {
					lines[i] = line + username
				} else {
					lines[i] = line + "," + username
				}
				os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
			}
			break
		}
	}
}
