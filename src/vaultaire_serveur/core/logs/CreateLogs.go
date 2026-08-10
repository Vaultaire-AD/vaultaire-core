package logs

import (
	"fmt"
	"os"
	"strings"
	"time"

	"vaultaire/core/storage"
)

// Logging uses RFC 5424 severity levels and writes to stdout (Twelve-Factor App).
// Logs are also kept in memory for the web UI (size-limited). See rfc5424.go.

// WriteLog écrit dans un fichier dédié.
//
// # Le niveau DATABASE a disparu
//
// « db » et « auth » étaient détournés vers un niveau nommé DATABASE, qui ne
// correspond à aucune sévérité RFC 5424 et que `Write_LogCode` ne filtrait pas :
// ces lignes étaient donc émises quel que soit le réglage, et impossibles à
// écarter.
//
// Les 145 appels concernés étaient TOUS sur un chemin d'erreur — vérifié par
// deux signaux indépendants, la présence d'un bloc `if err != nil` et le texte
// du message. Ils sont devenus des ERROR, ce qu'ils étaient déjà en fait, et
// ils se filtrent maintenant comme tout le reste.
//
// Cette fonction ne sert plus qu'à la journalisation FICHIER, pour les quelques
// familles qui en ont une : « date », « SQL_Injection ».
func WriteLog(filename string, content string) {
	content = strings.TrimSpace(content)

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
