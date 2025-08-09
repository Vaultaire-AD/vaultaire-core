package logs

import (
	"fmt"
	"os"
	"time"
)

func WriteLog(filename string, content string) error {
	// Définir le chemin du répertoire et du fichier
	dirPath := "/var/log/oppydoome/"
	filepath := dirPath + filename

	// Créer le répertoire s'il n'existe pas
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return fmt.Errorf("erreur lors de la création du répertoire: %v", err)
	}

	// Ouvre le fichier en mode append, le crée s'il n'existe pas
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("erreur lors de l'ouverture ou de la création du fichier: %v", err)
	}
	defer file.Close()

	// Formatte l'heure actuelle
	timestamp := time.Now().Format("2006-01-02 15:04")

	// Formatte la ligne à écrire [date/heure:minutes/contenu]
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, content)

	// Écrit la ligne dans le fichier
	if _, err := file.WriteString(logLine); err != nil {
		return fmt.Errorf("erreur lors de l'écriture dans le fichier: %v", err)
	}

	return nil
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
