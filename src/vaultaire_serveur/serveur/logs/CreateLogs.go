package logs

// <TIMESTAMP> [<LEVEL>] (<SOURCE>) <MESSAGE> [<METADATA>]

import (
	"vaultaire/serveur/storage"
	"fmt"
	"os"
	"strings"
	"time"
)

// Write_Log écrit une ligne de log (sans code). Pour le standard avec code d'erreur, utiliser Write_LogCode.
func Write_Log(level string, content string) {
	write_Log_impl(level, CodeNone, content)
}

// Write_LogCode écrit une ligne de log avec code d'erreur (standard VLT-XXX).
// Format: timestamp [LEVEL] [CODE] content
func Write_LogCode(level string, code string, content string) {
	write_Log_impl(level, code, content)
}

func write_Log_impl(level string, code string, content string) {
	if level == "DEBUG" && !storage.Debug {
		return
	}
	content = strings.TrimRight(content, "\n")
	dirPath := storage.LogPath
	filepath := dirPath + "vaultaire.log"

	if err := os.MkdirAll(dirPath, 0755); err != nil {
		fmt.Printf("erreur création répertoire log: %v", err)
		return
	}

	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("erreur ouverture fichier log: %v", err)
		return
	}
	defer file.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	var logLine string
	if code != "" {
		logLine = fmt.Sprintf("%s [%s] [%s] %s\n", timestamp, level, code, content)
	} else {
		logLine = fmt.Sprintf("%s [%s] %s\n", timestamp, level, content)
	}

	_ = Print_Log(logLine)
	_, _ = file.WriteString(logLine)
}

func Print_Log(logline string) error {
	fmt.Print(logline)
	return nil
}

// WriteLog écrit dans un fichier de log dédié (ex. "db"). Préférer Write_Log(level, code, content) pour le standard.
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
