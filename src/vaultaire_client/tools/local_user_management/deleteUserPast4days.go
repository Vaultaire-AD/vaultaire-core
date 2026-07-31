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
	defer file.Close()

	// On lit toutes les lignes une seule fois.
	var lines []string
	vaultaireUsers := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)

		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		comment := fields[4]
		shell := fields[6]

		if strings.Contains(comment, "vaultaire_user_account") &&
			(strings.HasSuffix(shell, "bash") || strings.HasSuffix(shell, "sh")) {
			vaultaireUsers++
		}
	}

	now := time.Now()

	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		username := fields[0]
		comment := fields[4]
		shell := fields[6]

		if !strings.Contains(comment, "vaultaire_user_account") {
			continue
		}

		if !strings.HasSuffix(shell, "bash") && !strings.HasSuffix(shell, "sh") {
			continue
		}

		out, err := exec.Command("lastlog", "-u", username).Output()
		if err != nil {
			log.Printf("Erreur avec lastlog pour %s: %v", username, err)
			continue
		}

		output := string(out)
		lastlogLines := strings.Split(output, "\n")
		if len(lastlogLines) < 2 {
			continue
		}

		expired := false

		if strings.Contains(lastlogLines[1], "**Never logged in**") {
			expired = true
		} else {
			fields = strings.Fields(lastlogLines[1])
			if len(fields) >= 5 {
				dateStr := strings.Join(fields[len(fields)-5:], " ")
				lastLoginTime, err := time.Parse("Mon Jan 2 15:04:05 2006", dateStr)
				if err == nil && now.Sub(lastLoginTime).Hours() > 96 {
					expired = true
				}
			}
		}

		if expired {
			// On ne supprime que s'il restera au moins 3 comptes Vaultaire.
			if vaultaireUsers-1 >= 3 {
				deleteUser(username)
				vaultaireUsers--
			} else {
				log.Printf("Compte %s expiré mais conservé : il ne resterait plus que %d comptes Vaultaire.",
					username, vaultaireUsers-1)
			}
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
