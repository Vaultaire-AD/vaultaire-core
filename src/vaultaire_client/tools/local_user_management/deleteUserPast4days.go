package localusermanagement

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DeleteUser_Vaultaire_Past_4Days_withoutconnection supprime les utilisateurs Vaultaire qui n'ont pas été connectés depuis plus de 4 jours
// se lance a chaque fois q'un utilisateur se connecte avec succés
func DeleteUser_Vaultaire_Past_4Days_withoutconnection() {
	passwdFile := "/etc/passwd"

	file, err := os.Open(passwdFile)
	if err != nil {
		log.Fatalf("Erreur d'ouverture de %s: %v", passwdFile, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Handle or log the error
			fmt.Printf("erreur lors de la fermeture du fichier: %v", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	now := time.Now()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 5 {
			continue
		}

		username := fields[0]
		comment := fields[4]
		shell := fields[6]

		// Ne traite que les comptes ayant le commentaire "vaultaire_user_account"
		if !strings.Contains(comment, "vaultaire_user_account") {
			continue
		}

		// Ignore les comptes sans shell "interactif"
		if !strings.HasSuffix(shell, "bash") && !strings.HasSuffix(shell, "sh") {
			continue
		}

		// Vérifie la dernière connexion via la commande `lastlog`
		out, err := exec.Command("lastlog", "-u", username).Output()
		if err != nil {
			log.Printf("Erreur avec lastlog pour %s: %v", username, err)
			continue
		}

		output := string(out)
		lines := strings.Split(output, "\n")
		if len(lines) < 2 {
			continue
		}

		if strings.Contains(lines[1], "**Never logged in**") {
			deleteUser(username)
			continue
		}

		// Exemple de ligne: username  pts/0  192.168.1.10  Mon Apr 29 15:04:05 2024
		fields = strings.Fields(lines[1])
		if len(fields) < 5 {
			continue
		}

		dateStr := strings.Join(fields[len(fields)-5:], " ")
		lastLoginTime, err := time.Parse("Mon Jan 2 15:04:05 2006", dateStr)
		if err != nil {
			log.Printf("Erreur parsing date pour %s: %v", username, err)
			continue
		}

		if now.Sub(lastLoginTime).Hours() > 96 {
			deleteUser(username)
		}
	}
}

func deleteUser(username string) {
	fmt.Printf("Suppression de l'utilisateur : %s\n", username)
	cmd := exec.Command("userdel", "-r", username)
	if err := cmd.Run(); err != nil {
		log.Printf("Erreur suppression de %s: %v", username, err)
	} else {
		log.Printf("Utilisateur %s supprimé avec succès.", username)
	}
}
