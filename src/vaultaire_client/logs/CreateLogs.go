package logs

import (
	"fmt"
	"os"
	"time"
	"vaultaire_client/storage"
)

func WriteLog(filename string, content string) {
	// Définir le chemin du répertoire et du fichier
	dirPath := "/var/log/oppydoome/"
	filepath := dirPath + filename

	// Créer le répertoire s'il n'existe pas
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		fmt.Printf("erreur lors de la création du répertoire: %v", err)
	}

	// Ouvre le fichier en mode append, le crée s'il n'existe pas
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("erreur lors de l'ouverture ou de la création du fichier: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Handle or log the error
			fmt.Printf("erreur lors de la fermeture du fichier: %v", err)
		}
	}()

	// Formatte l'heure actuelle
	timestamp := time.Now().Format("2006-01-02 15:04")

	// Formatte la ligne à écrire [date/heure:minutes/contenu]
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, content)

	// Écrit la ligne dans le fichier
	if _, err := file.WriteString(logLine); err != nil {
		fmt.Printf("erreur lors de l'écriture dans le fichier: %v", err)
	}
}

//func main() {
//	// Exemple d'utilisation
//	err := WriteLog("logfile.log", "Ceci est une ligne de log")
//	if err != nil {
//		fmt.Println("Erreur:", err)
//	} else {
//		fmt.Println("Log ajouté avec succès")
//	}
//}

func Write_Log(level string, content string) {
	// Si c'est un log DEBUG et que le mode debug est désactivé, on ignore
	if level == "DEBUG" && !storage.Debug {
		return
	}

	// Définir le chemin du répertoire et du fichier
	dirPath := storage.LogPath
	filepath := dirPath + "vaultaire_client.log"

	// Créer le répertoire s'il n'existe pas
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		fmt.Printf("erreur lors de la création du répertoire: %v", err)
	}

	// Ouvre le fichier en mode append, le crée s'il n'existe pas
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("erreur lors de l'ouverture ou de la création du fichier: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("erreur lors de la fermeture du fichier: %v", err)
		}
	}()

	// Formatte l'heure actuelle
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Formatte la ligne à écrire [date/heure niveau contenu]
	logLine := fmt.Sprintf("%s [%s] %s", timestamp, level, content)

	// Affiche dans la console
	if err := Print_Log(logLine); err != nil {
		fmt.Printf("erreur lors de l'impression du log: %v", err)
	}

	// Écrit dans le fichier
	if _, err := file.WriteString(logLine); err != nil {
		fmt.Printf("erreur lors de l'écriture dans le fichier: %v\n", err)
	}
}

func Print_Log(logline string) error {
	fmt.Println(logline)
	return nil
}
