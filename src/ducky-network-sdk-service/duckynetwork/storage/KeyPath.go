package storage

import (
	"os"
	"path/filepath"
	"strings"
)

// Emplacements sur disque, et leur résolution.
//
// # La règle, la même partout
//
//	variable d'environnement  →  valeur par défaut, modifiable par le programme
//
// L'environnement l'emporte parce qu'en conteneur, les chemins par défaut sont
// figés dans une image alors que l'environnement est ce qu'on ajuste au
// déploiement. C'est déjà le sens de la priorité retenu pour la configuration
// du core — voir config/env.go.
//
// Les variables ci-dessous restent des `var` et non des constantes : un
// programme qui embarque le socle peut leur donner sa propre valeur par défaut
// avant tout usage. L'agent le fait, parce que ses chemins historiques sont
// déjà déployés sur le parc et qu'en changer demanderait de toucher chaque
// machine.
//
// La résolution passe par les fonctions `…Resolu()` et non par la lecture
// directe des variables : c'est ce qui permet à l'environnement de gagner MÊME
// SI le programme a posé son défaut après le chargement du paquet. Lire la
// variable directement figerait l'ordre d'initialisation, qui n'est pas
// garanti entre paquets.
const (
	// EnvKeyPath : répertoire des clés et de l'identité.
	EnvKeyPath = "VAULTAIRE_KEY_PATH"
	// EnvLogPath : répertoire des journaux.
	EnvLogPath = "VAULTAIRE_LOG_PATH"
	// EnvClientSoftware : chemin COMPLET du fichier d'identité.
	//
	// Distinct de EnvKeyPath : l'identité vit normalement à côté des clés, mais
	// un déploiement peut vouloir la placer ailleurs — un volume persistant
	// séparé du volume de secrets, typiquement.
	EnvClientSoftware = "VAULTAIRE_CLIENT_SOFTWARE"
)

// KeyPath est le répertoire des clés et de l'identité.
//
// Contient client_software.yaml, private_key.pem, public.pem,
// serveurpublickey.pem et l'empreinte attestée du core. Il DOIT survivre aux
// redémarrages : sans persistance, un service se réenrôle à chaque lancement et
// épuise le quota de sa clé d'enrôlement.
var KeyPath = "/etc/vaultaire_client/.ssh"

// LogPath est le répertoire des journaux.
var LogPath = "/var/log/vaultaire/"

// NomJournal est le fichier de journal de CE programme, sans répertoire.
//
// # Pourquoi une variable et pas une constante
//
// Le SDK est partagé : l'agent et le proxy tournent tous deux dessus. Le nom
// était écrit en dur — « vaultaire_client.log » — et le proxy écrivait donc son
// journal dans le fichier de l'agent, sous un nom qui annonce autre chose que
// son contenu.
//
// Sans conséquence tant que les deux ne tournent pas sur la même machine ; sur
// la même, leurs lignes s'entrelacent dans un fichier qui n'appartient à
// personne. Et surtout, la rotation ne peut pas avoir de politique PAR ENTITÉ
// s'il n'y a qu'un fichier pour deux.
//
// Chaque programme la pose au démarrage, comme il pose déjà VersionComposant.
var NomJournal = "vaultaire_client.log"

// NomJournalResolu rend le nom de fichier de journal, jamais vide.
//
// Un nom vide donnerait un chemin qui désigne le RÉPERTOIRE : l'ouverture
// échouerait à chaque ligne, et le programme perdrait son journal en silence —
// puisque c'est précisément le journal qui aurait dû le dire.
func NomJournalResolu() string {
	if n := strings.TrimSpace(NomJournal); n != "" {
		return filepath.Base(n)
	}
	return "vaultaire.log"
}

// SoftwarePath est le chemin par défaut du fichier d'identité.
//
// Vide par défaut : la valeur est alors déduite de KeyPath, ce qui garde les
// deux ensemble. Une identité sans sa clé privée est inutilisable, et les
// séparer permettrait d'en sauvegarder une sans l'autre.
//
// La renseigner n'a de sens que pour un déploiement qui range vraiment les deux
// à des endroits différents.
var SoftwarePath = ""

// KeyPathResolu rend le répertoire des clés effectif.
func KeyPathResolu() string {
	if v := strings.TrimSpace(os.Getenv(EnvKeyPath)); v != "" {
		return filepath.Clean(v)
	}
	return filepath.Clean(KeyPath)
}

// LogPathResolu rend le répertoire des journaux effectif.
func LogPathResolu() string {
	if v := strings.TrimSpace(os.Getenv(EnvLogPath)); v != "" {
		return filepath.Clean(v) + string(filepath.Separator)
	}
	return LogPath
}

// SoftwarePathResolu rend le chemin effectif du fichier d'identité.
//
// Ordre : variable d'environnement, puis SoftwarePath s'il a été renseigné,
// puis KeyPath/client_software.yaml.
func SoftwarePathResolu() string {
	if v := strings.TrimSpace(os.Getenv(EnvClientSoftware)); v != "" {
		return filepath.Clean(v)
	}
	if v := strings.TrimSpace(SoftwarePath); v != "" {
		return filepath.Clean(v)
	}
	return filepath.Join(KeyPathResolu(), "client_software.yaml")
}

// CheminDansKeyPath rend le chemin d'un fichier du répertoire des clés.
//
// Une fonction plutôt que des filepath.Join dispersés : ils étaient une dizaine,
// chacun recopiant `storage.KeyPath`, et un seul oublié aurait continué de lire
// l'ancien emplacement après un changement de configuration.
func CheminDansKeyPath(nom string) string {
	return filepath.Join(KeyPathResolu(), nom)
}

// SilentConsole coupe l'écho des journaux sur la sortie standard.
//
// Un service en arrière-plan n'a pas de terminal : y écrire ne sert personne et
// la trace disparaît avec le processus. Les journaux de fichier ne sont pas
// affectés.
var SilentConsole = false

// Debug et DEBUG : verbosité.
//
// Les deux existaient dans l'agent, avec des valeurs opposées (Debug=true,
// DEBUG=false) et sans qu'aucun commentaire ne dise laquelle commande quoi.
// Elles sont conservées telles quelles pour ne rien changer au comportement de
// l'agent, mais toute nouvelle verbosité doit passer par SilentConsole.
var (
	Debug bool = true
	DEBUG bool = false
)
