package logs

import (
	"fmt"
	"os"
	"strings"
	"time"

	"vaultaire/serveur/storage"
)

// Logging uses RFC 5424 severity levels and writes to stdout (Twelve-Factor App).
// Logs are also kept in memory for the web UI (size-limited). See rfc5424.go.

// WriteLog writes to a dedicated log file or emits via RFC 5424.
// If filename is "db" or "auth", the message is sent to stdout only (no file) to avoid duplicates.
// Otherwise writes to dirPath+filename (legacy file logging).
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
