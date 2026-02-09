package logs

import (
	"vaultaire/serveur/storage"
	"fmt"
	"os"
	"strings"
	"time"
)

// Le système de logs utilise maintenant RFC 5424 et écrit sur stdout (Twelve-Factor App).
// Les logs sont également stockés en mémoire pour la web UI (avec limite de taille).
// Voir rfc5424.go pour l'implémentation.

// Write_Log et Write_LogCode sont maintenant définis dans rfc5424.go

// WriteLog écrit dans un fichier de log dédié ou émet en RFC 5424.
// Si filename == "db" ou "auth", le message est envoyé sur stdout en RFC 5424 (pas de fichier) pour éviter les doublons.
// Sinon, écrit dans dirPath+filename (compatibilité legacy).
func WriteLog(filename string, content string) {
	content = strings.TrimSpace(content)
	switch filename {
	case "db", "auth":
		Write_LogCode("ERROR", CodeDBGeneric, "database: "+content)
		return
	}

	dirPath := storage.LogPath
	filepath := dirPath + filename
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		Write_LogCode("ERROR", CodeFileConfig, "logs: mkdir failed: "+err.Error())
		return
	}
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		Write_LogCode("ERROR", CodeFileConfig, "logs: open file failed: "+err.Error())
		return
	}
	defer file.Close()
	timestamp := time.Now().Format("2006-01-02 15:04")
	if _, err := file.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, content)); err != nil {
		Write_LogCode("ERROR", CodeFileConfig, "logs: write file failed: "+err.Error())
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
