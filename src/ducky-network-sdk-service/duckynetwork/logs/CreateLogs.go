package logs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// Journalisation FICHIER du socle.
//
// # Le fichier est rouvert PAR SON CHEMIN à chaque ligne
//
// C'est ce qui permet à la rotation d'être un simple renommage, sans aucune
// gestion de descripteur. Un programme qui garderait le fichier ouvert
// continuerait d'écrire dans le fichier RENOMMÉ — donc dans l'archive — et le
// fichier courant resterait vide indéfiniment.
//
// Ici, chaque ligne fait un `OpenFile` sur le CHEMIN : après un renommage, la
// ligne suivante recrée le fichier. Cela vaut pour la rotation que fait ce
// paquet (voir rotation.go), et aussi pour un administrateur qui déplacerait le
// fichier à la main.
//
// Le coût est réel — quelques appels système par ligne — et il est assumé. Le
// volume d'un agent se compte en dizaines de lignes par minute, pas en milliers
// par seconde. Le jour où ce ne sera plus vrai, garder le descripteur exigera de
// rendre la rotation consciente de ce descripteur DANS LE MÊME GESTE, sans quoi
// le journal disparaîtra silencieusement à la première rotation.

// # Un second répertoire, que personne ne surveillait
//
// `WriteLog` écrivait dans « /var/log/vaultaire_client/ », en dur, alors que le
// journal principal va dans storage.LogPath — « /var/log/vaultaire/ ». Deux
// répertoires, dont un seul est créé par l'installeur et protégé en 0700 ;
// l'autre naissait au vol en 0755, lisible par tout le monde, et aucune rotation
// ne l'aurait couvert.
//
// Les deux fonctions résolvent désormais le même répertoire. Un déploiement
// existant peut contenir l'ancien : la documentation d'exploitation dit quoi en
// faire.

// modeRepertoireJournal : les journaux d'un agent nomment des comptes et des
// machines. 0700 plutôt que 0755, comme le répertoire posé par l'installeur.
const modeRepertoireJournal = 0o700

// WriteLog écrit dans un fichier dédié à une famille d'événements.
//
// La famille devient un nom de fichier : elle est donc VALIDÉE. Sans cela, un
// appelant peut créer un fichier arbitraire — c'est déjà arrivé, avec un appel
// qui passait un niveau de journal en guise de famille — et surtout un chemin
// contenant « / » ou « .. » sortirait du répertoire.
func WriteLog(famille string, content string) {
	nom, ok := nomDeFichierFamille(famille)
	if !ok {
		Write_log("ERROR", "logs: famille de journal refusée : "+famille)
		return
	}
	ecrireLigne(storage.LogPathResolu()+nom, content)
}

// nomDeFichierFamille valide une famille et rend le nom de fichier.
//
// Le suffixe « .log » est ajouté pour que la rotation puisse cibler un motif
// unique. Les fichiers portaient jusqu'ici le nom brut de la famille — « date »,
// « error » — que rien ne distinguait d'un répertoire ou d'un fichier de travail.
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

// Write_log écrit une ligne dans le journal principal du programme.
func Write_log(level string, content string) {
	if level == "DEBUG" && !storage.DEBUG {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("%s [%s] %s", timestamp, level, content)

	// La console d'abord : si l'écriture fichier échoue — disque plein, droits —
	// la ligne a au moins été vue quelque part. L'ordre inverse ferait perdre les
	// deux à la fois, au moment précis où l'on a besoin de savoir.
	if err := Print_Log(logLine); err != nil {
		fmt.Printf("erreur lors de l'impression du log: %v\n", err)
	}

	ecrireLigne(storage.LogPathResolu()+storage.NomJournalResolu(), logLine)
}

// verrouEcriture sérialise l'écriture ET la rotation.
//
// Sans lui, deux goroutines pourraient décider de faire tourner le même fichier
// au même instant : la seconde renommerait le fichier neuf que la première vient
// de créer, et les lignes de la première partiraient en archive.
//
// Il sérialise aussi les écritures ordinaires, ce qui n'est pas gênant à ces
// volumes et évite de dépendre de l'atomicité de O_APPEND.
var verrouEcriture sync.Mutex

// ecrireLigne ajoute une ligne à un fichier, en le créant au besoin.
//
// Les erreurs vont sur la sortie standard et NON dans le journal : écrire dans
// le journal l'échec d'écriture du journal se rappellerait indéfiniment.
func ecrireLigne(chemin string, ligne string) {
	verrouEcriture.Lock()
	defer verrouEcriture.Unlock()

	if err := os.MkdirAll(filepath.Dir(chemin), modeRepertoireJournal); err != nil {
		fmt.Printf("erreur lors de la création du répertoire de journal: %v\n", err)
		return
	}

	// La rotation AVANT l'ouverture, jamais après : décidée sur un fichier
	// qu'on vient d'agrandir, elle archiverait un fichier contenant déjà la
	// ligne du jour suivant.
	rotationSiNecessaire(chemin)

	// 0600 : un journal d'agent nomme des comptes, des machines et des motifs de
	// refus. Il était en 0644, donc lisible par tout utilisateur de la machine —
	// y compris ceux dont il raconte les tentatives de connexion.
	file, err := os.OpenFile(chemin, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Printf("erreur lors de l'ouverture du fichier de journal: %v\n", err)
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("erreur lors de la fermeture du fichier de journal: %v\n", err)
		}
	}()

	if _, err := file.WriteString(strings.TrimRight(ligne, "\n") + "\n"); err != nil {
		fmt.Printf("erreur lors de l'écriture dans le fichier de journal: %v\n", err)
	}
}

// Print_Log affiche une ligne sur la sortie standard.
//
// Silencieux en mode « fetch SSH » : la sortie standard est alors le canal de
// réponse lu par le module PAM, et y écrire une ligne de journal la corromprait.
func Print_Log(logline string) error {
	if storage.SilentConsole {
		return nil
	}
	fmt.Println(logline)
	return nil
}
