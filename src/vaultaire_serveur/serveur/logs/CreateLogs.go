package logs

// <TIMESTAMP> [<LEVEL>] (<SOURCE>) <MESSAGE> [<METADATA>]

import (
	"DUCKY/serveur/storage"
	"fmt"
	"os"
	"time"
)

// Write_Log écrit une ligne de log dans le fichier vaultaire.log.
// Cette fonction est utilisée pour enregistrer des messages de log avec un niveau de gravité.
// Le niveau de log peut être "INFO", "WARNING", "ERROR", etc.
// Le contenu du log est le message à enregistrer.
// Le format de la ligne de log est [date/heure:minutes/contenu].
// Le fichier de log est créé s'il n'existe pas, et les logs sont ajoutés à la fin du fichier.
// Write_Log prend en paramètre le niveau de log et le contenu du message à enregistrer.
// Elle crée le répertoire de logs s'il n'existe pas et ouvre le fichier en mode append.
// Si une erreur survient lors de la création du répertoire, de l'ouverture du fichier ou de l'écriture dans le fichier, elle renvoie une erreur.
func Write_Log(level string, content string) {
	// Définir le chemin du répertoire et du fichier
	dirPath := storage.LogPath
	filepath := dirPath + "vaultaire.log"

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
	defer file.Close()

	// Formatte l'heure actuelle
	timestamp := time.Now().Format("2006-01-02 15:04:56")

	// Formatte la ligne à écrire [date/heure:minutes/contenu]
	logLine := fmt.Sprintf("%s [%s] %s\n", timestamp, level, content)
	err = Print_Log(logLine)
	if err != nil {
		fmt.Printf("erreur lors de l'impression du log: %v", err)
	}
	if _, err := file.WriteString(logLine); err != nil {
		fmt.Printf("erreur lors de l'écriture dans le fichier: %v\n", err)
	}
}

func Print_Log(logline string) error {
	fmt.Println(logline)
	return nil
}

// WriteLog écrit une ligne de log dans un fichier spécifié.
// Cette fonction est utilisée pour écrire des logs dans un fichier spécifique.
// Le fichier est créé s'il n'existe pas, et les logs sont ajoutés à la fin du fichier.
// Le format de la ligne de log est [date/heure:minutes/contenu].
// Le paramètre 'filename' spécifie le nom du fichier de log, et 'content' est le message à enregistrer.
func WriteLog(filename string, content string) {
	// Définir le chemin du répertoire et du fichier
	dirPath := storage.LogPath
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
	defer file.Close()

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
