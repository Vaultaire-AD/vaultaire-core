package gpo

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func ApplyGPOsAsUser(username, commandsStr string) error {
	// Trouve l'utilisateur
	targetUser, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("utilisateur %s introuvable: %v", username, err)
	}

	uid, _ := strconv.Atoi(targetUser.Uid)
	gid, _ := strconv.Atoi(targetUser.Gid)

	// commands := strings.Split(commandsStr, "\n")
	// for _, cmdLine := range commands {
	// 	cmdLine = strings.TrimSpace(cmdLine)
	// 	if cmdLine == "" {
	// 		continue
	// 	}

	// 	args := strings.Fields(cmdLine)
	// 	if len(args) == 0 {
	// 		continue
	// 	}

	cmd := exec.Command(commandsStr)

	// TRÈS IMPORTANT : On définit l'utilisateur pour le process
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}

	// (Optionnel) set l'environnement du user
	cmd.Env = append(cmd.Env, "HOME="+targetUser.HomeDir)

	// Récupère output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("erreur en exécutant '%s' : %v\nSortie:\n%s", commandsStr, err, string(output))
	}

	fmt.Printf("Commande réussie pour %s : %s\nSortie:\n%s\n", username, commandsStr, string(output))
	// }
	return nil
}
