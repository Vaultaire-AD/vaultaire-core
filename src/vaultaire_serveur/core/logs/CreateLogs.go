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
//
// # Le fichier est rouvert PAR SON CHEMIN à chaque ligne
//
// C'est ce qui rend `logrotate` suffisant sans une ligne de code de rotation, et
// la propriété est trop facile à détruire pour rester implicite.
//
// logrotate RENOMME le fichier puis en crée un neuf. Un programme qui garderait
// un descripteur ouvert continuerait d'écrire dans le fichier renommé — donc
// dans l'archive — et le fichier courant resterait vide indéfiniment. C'est le
// défaut classique, celui qui oblige à `copytruncate` (qui perd les lignes
// écrites pendant la copie) ou à un signal de réouverture.
//
// Ici, chaque ligne fait un `OpenFile` sur le CHEMIN : après un renommage, la
// ligne suivante recrée le fichier. Le volume de ces deux familles se compte en
// quelques lignes par jour ; le coût des deux appels système est sans objet.
func WriteLog(famille string, content string) {
	content = strings.TrimSpace(content)

	nom, ok := nomDeFichierFamille(famille)
	if !ok {
		Write_LogCode("ERROR", CodeFileConfig,
			"logs: famille de journal refusée : "+famille)
		return
	}

	dirPath := storage.LogPath
	// 0700 : ces fichiers nomment des comptes et des tentatives d'injection. Ils
	// étaient créés en 0755, donc lisibles par tout utilisateur de la machine.
	if err := os.MkdirAll(dirPath, 0o700); err != nil {
		Write_LogCode("ERROR", CodeFileConfig, "logs: mkdir failed: "+err.Error())
		return
	}
	file, err := os.OpenFile(dirPath+nom, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		Write_LogCode("ERROR", CodeFileConfig, "logs: open file failed: "+err.Error())
		return
	}
	defer file.Close()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	if _, err := file.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, content)); err != nil {
		Write_LogCode("ERROR", CodeFileConfig, "logs: write file failed: "+err.Error())
	}
}

// nomDeFichierFamille valide une famille et rend le nom de fichier.
//
// La famille devient un nom de fichier : elle est donc VALIDÉE. Un appelant
// pouvait créer un fichier arbitraire — c'est arrivé, avec un appel qui passait
// « WARNING » en guise de famille et déposait un fichier de ce nom — et un
// chemin contenant « / » ou « .. » sortirait du répertoire.
//
// Le suffixe « .log » est ajouté pour que la rotation cible un motif unique.
// Les fichiers portaient le nom brut de la famille, que rien ne distinguait
// d'un répertoire ou d'un fichier de travail.
func nomDeFichierFamille(famille string) (string, bool) {
	f := strings.TrimSpace(famille)
	if f == "" || len(f) > 64 {
		return "", false
	}
	for _, r := range f {
		estAutorise := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-'
		if !estAutorise {
			return "", false
		}
	}
	return f + ".log", true
}
