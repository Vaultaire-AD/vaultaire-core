package autoaddclientgo

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

//
//func ExecuterCommandesSSHAvecCle(user, privateKeyPath, host string, port int) error {
//	remote := fmt.Sprintf("%s@%s", user, host)
//
//	// Étape 1 : récupérer le nom de l'OS
//	cmdDetect := exec.Command("ssh", "-i", privateKeyPath, "-p", fmt.Sprintf("%d", port), remote, "cat /etc/os-release")
//	var out bytes.Buffer
//	var stderr bytes.Buffer
//	cmdDetect.Stdout = &out
//	cmdDetect.Stderr = &stderr
//
//	if err := cmdDetect.Run(); err != nil {
//		return fmt.Errorf("❌ Impossible de détecter l'OS distant : %s\n%s", err, stderr.String())
//	}
//
//	osRelease := out.String()
//	var osType string
//	switch {
//	case strings.Contains(osRelease, "ID=debian"):
//		osType = "debian"
//		err := LoadCommandsFromShellScript(storage.Sh_folder_path + osType + ".sh")
//		if err != nil {
//			return fmt.Errorf("%s", "failed to load command file"+err.Error())
//		}
//	case strings.Contains(osRelease, "ID=ubuntu"):
//		osType = "ubuntu"
//		err := LoadCommandsFromShellScript(storage.Sh_folder_path + osType + ".sh")
//		if err != nil {
//			return fmt.Errorf("%s", "failed to load command file"+err.Error())
//		}
//	case strings.Contains(osRelease, "ID=\"rocky\"") || strings.Contains(osRelease, "ID=rocky"):
//		osType = "rocky"
//		err := LoadCommandsFromShellScript(storage.Sh_folder_path + osType + ".sh")
//		if err != nil {
//			return fmt.Errorf("%s", "failed to load command file"+err.Error())
//		}
//	default:
//		return fmt.Errorf("⚠️ OS non reconnu :\n%s", osRelease)
//	}
//
//	fmt.Printf("✅ OS détecté : %s\n", osType)
//	// Exécution des commandes en SSH
//	for _, commande := range storage.AutoAddClientCommandesList {
//
//		fullCommand := fmt.Sprintf("bash -c '%s'", escapeSingleQuotes(commande))
//
//		cmd := exec.Command("ssh", "-i", privateKeyPath, "-p", fmt.Sprintf("%d", port), remote, fullCommand)
//
//		var stderr bytes.Buffer
//		cmd.Stderr = &stderr
//
//		fmt.Printf("▶️  %s\n", commande)
//		if err := cmd.Run(); err != nil {
//			return fmt.Errorf("❌ Erreur commande : %s\n%s", commande, stderr.String())
//		}
//	}
//
//	fmt.Println("✅ Toutes les commandes ont été exécutées avec succès.")
//	return nil
//}
//

func ExecuterCommandesSSHAvecCle(user, privateKeyPath, host string, port int) error {
	remote := fmt.Sprintf("%s@%s", user, host)
	portStr := fmt.Sprintf("%d", port)

	// 1. Détecter l'OS distant (identique à votre code)
	cmdDetect := exec.Command("ssh", "-i", privateKeyPath, "-p", portStr, remote, "cat /etc/os-release")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmdDetect.Stdout = &out
	cmdDetect.Stderr = &stderr

	if err := cmdDetect.Run(); err != nil {
		return fmt.Errorf("❌ Impossible de détecter l'OS distant : %s\n%s", err, stderr.String())
	}

	osRelease := out.String()
	script, distribution, err := ScriptDInstallation(osRelease)
	if err != nil {
		return fmt.Errorf("⚠️ %v", err)
	}

	localScriptPath := storage.Sh_folder_path + script
	if _, errStat := os.Stat(localScriptPath); errStat != nil {
		// Dit ICI, et non par l'échec du transfert : « scp : exit status 1 » ne
		// nommait ni le fichier ni la raison (TO-DO 71).
		return fmt.Errorf("❌ script d'installation %s introuvable sur ce core (%v) : "+
			"le répertoire sh_folder_path est-il complet ?", localScriptPath, errStat)
	}
	remoteScriptPath := "/tmp/vaultaire_install.sh"

	logs.Write_Log("INFO", fmt.Sprintf("autoadd : %s détecté sur %s, transfert du script %s", distribution, host, script))

	// 2. Transférer le script sur le serveur distant via SCP
	scpCmd := exec.Command("scp", "-i", privateKeyPath, "-P", portStr, localScriptPath, fmt.Sprintf("%s:%s", remote, remoteScriptPath))
	var scpErr bytes.Buffer
	scpCmd.Stderr = &scpErr
	if err := scpCmd.Run(); err != nil {
		return fmt.Errorf("❌ Erreur lors du transfert du script via SCP : %v\n%s", err, scpErr.String())
	}

	// 3. Exécuter le script distant en tant que root/bash.
	//
	// La sortie du script allait sur la sortie standard du core (TO-DO 153) :
	// invisible pour l'administrateur qui lançait la commande à distance, et
	// absente du journal. Elle est maintenant gardée — sa fin seulement, le
	// script d'installation est bavard — et jointe à l'erreur en cas d'échec.
	runCmd := exec.Command("ssh", "-i", privateKeyPath, "-p", portStr, remote, fmt.Sprintf("bash %s", remoteScriptPath))
	sortie := &FinDeSortie{Max: TailleFinDeSortie}
	runCmd.Stdout = sortie
	runCmd.Stderr = sortie

	logs.Write_Log("DEBUG", "autoadd : exécution du script d'installation sur "+host)
	if err := runCmd.Run(); err != nil {
		return fmt.Errorf("❌ Erreur lors de l'exécution du script distant : %v\n--- fin de la sortie du script ---\n%s", err, sortie.String())
	}

	logs.Write_Log("INFO", "autoadd : script d'installation joué avec succès sur "+host)
	return nil
}

// TailleFinDeSortie borne ce qu'on garde de la sortie du script distant : assez
// pour voir l'erreur d'apt ou de dnf qui l'a fait échouer, pas tout le journal
// d'installation des paquets.
const TailleFinDeSortie = 4096

// FinDeSortie est un io.Writer qui ne garde que les Max derniers octets écrits.
// Stdout et Stderr d'une même commande peuvent le partager : exec ne les
// écrit pas en parallèle quand c'est le même Writer.
type FinDeSortie struct {
	Max     int
	donnees []byte
	coupe   bool
}

func (f *FinDeSortie) Write(p []byte) (int, error) {
	f.donnees = append(f.donnees, p...)
	if f.Max > 0 && len(f.donnees) > f.Max {
		f.donnees = append(f.donnees[:0:0], f.donnees[len(f.donnees)-f.Max:]...)
		f.coupe = true
	}
	return len(p), nil
}

// String rend la fin gardée, précédée de « … » si le début a été coupé.
func (f *FinDeSortie) String() string {
	if f.coupe {
		return "…" + string(f.donnees)
	}
	return string(f.donnees)
}

func escapeSingleQuotes(cmd string) string {
	// Transforme chaque ' en '\'' (échappement POSIX pour bash -c '')
	return strings.ReplaceAll(cmd, "'", "'\\''")
}

// ScriptDInstallation choisit le script à jouer sur un poste, d'après son
// /etc/os-release. Rend le nom du fichier et la distribution reconnue.
//
// # Ce qui a changé — TO-DO 71
//
// Le choix cherchait « ID=debian » ou « ID=ubuntu » N'IMPORTE OÙ dans le
// fichier, puis demandait « debian.sh » ou « ubuntu.sh » — deux scripts qui
// n'existaient pas. Sur un poste Debian ou Ubuntu, l'installation échouait au
// transfert, sur un message qui ne nommait rien.
//
// Debian et Ubuntu partagent maintenant UN script, debian.sh : ce qui les
// distingue de Rocky — apt, le répertoire multiarch, des piles PAM en
// « @include common-auth » — leur est commun.
//
// # Seulement la ligne ID
//
// La distribution est lue sur la ligne `ID=`, et elle seule. Chercher le texte
// partout reconnaissait aussi « VARIANT_ID=debian », ou un commentaire. Et
// `ID_LIKE` n'est PAS suivi : il dit de qui une distribution descend, pas
// qu'elle se comporte pareil. Un script qui réécrit PAM ne se joue pas sur une
// machine parce qu'elle « ressemble » à une autre ; une distribution non
// reconnue reçoit un refus, qui nomme ce qui a été lu.
func ScriptDInstallation(osRelease string) (script, distribution string, err error) {
	id := ""
	for _, ligne := range strings.Split(osRelease, "\n") {
		ligne = strings.TrimSpace(ligne)
		if valeur, ok := strings.CutPrefix(ligne, "ID="); ok {
			id = strings.ToLower(strings.Trim(strings.TrimSpace(valeur), `"'`))
			break
		}
	}
	switch id {
	case "debian", "ubuntu":
		return "debian.sh", id, nil
	case "rocky":
		return "rocky.sh", id, nil
	case "":
		return "", "", fmt.Errorf("distribution illisible : aucune ligne ID= dans /etc/os-release")
	default:
		return "", "", fmt.Errorf("distribution %q non prise en charge par l'installation à distance "+
			"(prises en charge : debian, ubuntu, rocky)", id)
	}
}
