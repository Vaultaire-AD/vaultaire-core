package autoaddclientgo

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// ExecuterCommandesSSHAvecCle choisit le script d'installation du poste, le
// dépose par SFTP et l'exécute, sur la connexion déjà ouverte.
func ExecuterCommandesSSHAvecCle(client *ssh.Client, host string) error {
	// 1. Détecter l'OS distant
	osRelease, err := lireSortie(client, "cat /etc/os-release")
	if err != nil {
		return fmt.Errorf("❌ Impossible de détecter l'OS distant : %v", err)
	}

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
	// Dans le répertoire personnel du compte de connexion, et non dans /tmp
	// (recette du 28/10) : un chemin fixe dans un répertoire où tout le monde
	// écrit laisse un compte local du poste préparer le fichier que root va
	// exécuter. Effacé après l'exécution, réussie ou non.
	remoteScriptPath := ScriptDistant

	logs.Write_Log("INFO", fmt.Sprintf("autoadd : %s détecté sur %s, transfert du script %s", distribution, host, script))

	// 2. Transférer le script (SFTP : un chemin relatif part du répertoire
	// personnel, comme le faisait scp). 0600 : il n'est lu que par bash.
	sc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("❌ sous-système sftp indisponible sur le poste : %v", err)
	}
	err = copierFichier(sc, localScriptPath, remoteScriptPath, 0o600)
	sc.Close()
	if err != nil {
		return fmt.Errorf("❌ Erreur lors du transfert du script : %v", err)
	}

	// 3. Exécuter le script distant.
	//
	// La sortie est gardée — sa fin seulement, le script d'installation est
	// bavard — et jointe à l'erreur en cas d'échec (TO-DO 153).
	sortie := &FinDeSortie{Max: TailleFinDeSortie}
	logs.Write_Log("DEBUG", "autoadd : exécution du script d'installation sur "+host)
	if err := executer(client, CommandeDistante(remoteScriptPath), sortie); err != nil {
		return fmt.Errorf("❌ Erreur lors de l'exécution du script distant : %v\n--- fin de la sortie du script ---\n%s", err, sortie.String())
	}

	logs.Write_Log("INFO", "autoadd : script d'installation joué avec succès sur "+host)
	return nil
}

// ScriptDistant : chemin RELATIF, donc dans le répertoire personnel du compte
// de connexion (SFTP et SSH y partent), qui n'est pas inscriptible par les
// autres comptes du poste.
const ScriptDistant = ".vaultaire_install.sh"

// CommandeDistante exécute le script, l'efface, et rend son code de sortie.
func CommandeDistante(script string) string {
	return fmt.Sprintf("bash %s; s=$?; rm -f %s; exit $s", script, script)
}

// TailleFinDeSortie borne ce qu'on garde de la sortie du script distant : assez
// pour voir l'erreur d'apt ou de dnf qui l'a fait échouer, pas tout le journal
// d'installation des paquets.
const TailleFinDeSortie = 4096

// FinDeSortie est un io.Writer qui ne garde que les Max derniers octets écrits.
// Stdout et Stderr d'une même session SSH le partagent : ssh.Session ne les
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
