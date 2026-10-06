package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
)

// Configuration de l'agent : /etc/vaultaire_client/client_conf.json.
//
//	{
//	  "servers": [ {"ip": "10.0.0.10", "port": 6666}, … ],
//	  "learned": [ {"ip": "10.0.0.11", "port": 6666, "hostname": "core-b", "role": "core"}, … ],
//	  "debug":   { "enabled": false, "interval_seconds": 60 }
//	}
//
// # Deux listes de serveurs, et pourquoi
//
// `servers` est écrite à l'installation (`vlt create -c … -join`) : la liste des
// cores exposés au moment du déploiement. L'agent ne la réécrit JAMAIS — elle
// est le dernier recours, celui qui reste quand tout ce qui a été appris est
// faux ou éteint.
//
// `learned` est écrite par l'agent lui-même, à chaque liste 04_04 qui change
// (TO-DO 61). Avant, la liste apprise ne vivait qu'en mémoire : au redémarrage,
// l'agent repartait de la seule adresse du fichier, et si ce core avait été
// retiré, il ne joignait plus personne.
//
// Ordre d'essai : appris en mémoire (session en cours), puis `learned`, puis
// `servers` — voir AdressesConnues et decouverte.FusionnerAdresses.

// ServerConfig est une adresse de nœud. Hostname et Role ne servent qu'à
// l'affichage (rapport de debug) : l'agent ne décide rien sur leur foi.
type ServerConfig struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname,omitempty"`
	Role     string `json:"role,omitempty"`
}

// Adresse rend « ip:port ».
func (s ServerConfig) Adresse() string { return s.IP + ":" + strconv.Itoa(s.Port) }

// DebugConfig règle le rapport de debug périodique (voir paquet debugreport).
type DebugConfig struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"interval_seconds,omitempty"`
}

// Config est le contenu du fichier.
type Config struct {
	Servers []ServerConfig `json:"servers"`
	Learned []ServerConfig `json:"learned,omitempty"`
	Debug   *DebugConfig   `json:"debug,omitempty"`
}

var (
	// Configuration est l'état en mémoire. Lire par les accesseurs : elle est
	// réécrite à chaud par MettreAJourAppris.
	Configuration Config
	configMutex   sync.RWMutex
	configPath    string
)

// IntervalleDebugParDefaut est la période du rapport de debug.
const IntervalleDebugParDefaut = 60

// marqueurBOM est la marque d'ordre des octets UTF-8 (U+FEFF, EF BB BF).
//
// Elle n'a aucune utilité en UTF-8 — il n'y a pas d'ordre d'octets à marquer —
// mais Windows en met partout : le Bloc-notes, `Set-Content -Encoding UTF8` de
// Windows PowerShell 5.1, et la plupart des éditeurs par défaut.
var marqueurBOM = []byte{0xEF, 0xBB, 0xBF}

// sansBOM retire la marque d'ordre des octets en tête de fichier.
//
// # Le défaut que cela corrige
//
// `encoding/json` refuse un document qui commence par un BOM : la norme JSON ne
// l'autorise pas, et le décodeur signale « invalid character 'ï' ». L'installeur
// Windows écrivait `client_conf.json` avec `Set-Content -Encoding UTF8`, qui en
// ajoute un — l'agent ne lisait donc jamais sa configuration, avec un message
// qui n'évoquait rien pour personne (recette du 24/09).
//
// L'installeur est corrigé, mais ce filtre reste : n'importe qui peut ouvrir ce
// fichier dans le Bloc-notes pour ajouter un core et le réenregistrer. Refuser
// une configuration valide pour trois octets invisibles serait une mauvaise
// manière de faire respecter la norme.
func sansBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, marqueurBOM)
}

// LoadConfig charge le fichier JSON et remplace la configuration en mémoire.
func LoadConfig(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	var c Config
	if err := json.Unmarshal(sansBOM(data), &c); err != nil {
		return fmt.Errorf("%s illisible : %w", filePath, err)
	}
	configMutex.Lock()
	configPath = filePath
	Configuration = c
	configMutex.Unlock()
	return nil
}

// Chemin rend le fichier chargé.
func Chemin() string {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return configPath
}

// GetServers rend une copie de la liste d'installation.
func GetServers() []ServerConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return append([]ServerConfig(nil), Configuration.Servers...)
}

// GetLearned rend une copie de la liste apprise persistée.
func GetLearned() []ServerConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return append([]ServerConfig(nil), Configuration.Learned...)
}

// GetDebug rend le réglage de debug, intervalle ramené au défaut s'il est absent.
func GetDebug() DebugConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()
	d := DebugConfig{IntervalSeconds: IntervalleDebugParDefaut}
	if Configuration.Debug != nil {
		d.Enabled = Configuration.Debug.Enabled
		if Configuration.Debug.IntervalSeconds > 0 {
			d.IntervalSeconds = Configuration.Debug.IntervalSeconds
		}
	}
	return d
}

// AdressesConnues rend les adresses « ip:port » du fichier : apprises d'abord,
// puis celles de l'installation, sans doublon.
func AdressesConnues() []string {
	configMutex.RLock()
	defer configMutex.RUnlock()
	vues := map[string]bool{}
	var out []string
	for _, l := range [][]ServerConfig{Configuration.Learned, Configuration.Servers} {
		for _, s := range l {
			if s.IP == "" || s.Port <= 0 {
				continue
			}
			a := s.Adresse()
			if !vues[a] {
				vues[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// MettreAJourAppris remplace la liste apprise, en mémoire ET dans le fichier.
//
// Rend faux, sans rien écrire, si la liste est identique : une 04_04 arrive
// toutes les 30 minutes, et réécrire un fichier de configuration à chaque fois
// pour rien use le disque et brouille les dates de modification.
//
// Une liste vide ne remplace rien — même règle que decouverte.Enregistrer : un
// core qui n'annonce aucun nœud va peut-être mal, et l'agent ne doit pas perdre
// ce qu'il savait au moment précis où il en a besoin.
//
// La mémoire n'est mise à jour qu'APRÈS l'écriture réussie : sinon l'agent
// croirait avoir persisté ce qu'un redémarrage effacerait.
func MettreAJourAppris(noeuds []ServerConfig) (bool, error) {
	if len(noeuds) == 0 {
		return false, nil
	}
	configMutex.Lock()
	defer configMutex.Unlock()
	if reflect.DeepEqual(Configuration.Learned, noeuds) {
		return false, nil
	}
	nouvelle := Configuration
	nouvelle.Learned = append([]ServerConfig(nil), noeuds...)
	if err := ecrire(configPath, nouvelle); err != nil {
		return false, err
	}
	Configuration = nouvelle
	return true, nil
}

// SaveConfig écrit une configuration complète et la rend active.
func SaveConfig(newConfig Config) error {
	configMutex.Lock()
	defer configMutex.Unlock()
	if err := ecrire(configPath, newConfig); err != nil {
		return err
	}
	Configuration = newConfig
	return nil
}

// ReloadConfig recharge la configuration depuis le fichier actuel.
func ReloadConfig() error {
	p := Chemin()
	if p == "" {
		return fmt.Errorf("aucun fichier de configuration chargé")
	}
	return LoadConfig(p)
}

// ecrire écrit de façon ATOMIQUE : fichier temporaire, fsync, renommage.
//
// Un agent coupé au milieu d'une écriture directe laisserait un JSON tronqué,
// que LoadConfig refuse au démarrage suivant — l'agent ne démarrerait plus du
// tout, pour une liste qui n'était qu'une commodité.
//
// Les droits du fichier existant sont conservés (0600 par défaut).
func ecrire(chemin string, c Config) error {
	if chemin == "" {
		return fmt.Errorf("aucun fichier de configuration chargé")
	}
	data, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	mode := os.FileMode(0o600)
	if st, err := os.Stat(chemin); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(chemin), ".client_conf-*.tmp")
	if err != nil {
		return fmt.Errorf("écriture de %s : %w", chemin, err)
	}
	nom := tmp.Name()
	echec := func(e error) error {
		tmp.Close()
		os.Remove(nom)
		return fmt.Errorf("écriture de %s : %w", chemin, e)
	}
	if _, err := tmp.Write(data); err != nil {
		return echec(err)
	}
	if err := tmp.Sync(); err != nil {
		return echec(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(nom)
		return fmt.Errorf("écriture de %s : %w", chemin, err)
	}
	if err := os.Chmod(nom, mode); err != nil {
		os.Remove(nom)
		return fmt.Errorf("écriture de %s : %w", chemin, err)
	}
	if err := os.Rename(nom, chemin); err != nil {
		os.Remove(nom)
		return fmt.Errorf("écriture de %s : %w", chemin, err)
	}
	return nil
}
