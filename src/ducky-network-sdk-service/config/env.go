package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Variables d'environnement reconnues.
//
// Elles l'emportent sur le fichier, et c'est le bon sens de la priorité : en
// conteneur, le fichier est figé dans une image ou un volume alors que
// l'environnement est ce qu'on ajuste au déploiement. L'inverse obligerait à
// reconstruire pour changer d'adresse de core.
const (
	// EnvCore : « ip:port », ou plusieurs séparés par des virgules.
	EnvCore = "VAULTAIRE_IP_CORE"
	// EnvEnrollKey : la clé d'enrôlement.
	EnvEnrollKey = "VAULTAIRE_ENROLL_KEY"
	// EnvEnrollLabel : le libellé affiché côté core.
	EnvEnrollLabel = "VAULTAIRE_ENROLL_LABEL"
)

// DefaultDuckyPort est le port du réseau Ducky sur le core.
//
// Permet d'écrire VAULTAIRE_IP_CORE=10.0.0.1 sans le port. Le port explicite
// reste possible et l'emporte.
const DefaultDuckyPort = 6666

// applyEnv superpose l'environnement au fichier.
//
// # Pourquoi la clé d'enrôlement surtout
//
// C'est le seul secret de la configuration. Le passer par l'environnement
// permet de le tenir hors du dépôt et hors de l'image : un fichier de
// configuration contenant une clé valide finit toujours par être commité.
func applyEnv(cfg *Config) error {
	if v := strings.TrimSpace(os.Getenv(EnvCore)); v != "" {
		servers, err := ParseServers(v)
		if err != nil {
			return fmt.Errorf("%s : %w", EnvCore, err)
		}
		// REMPLACE la liste du fichier au lieu de s'y ajouter.
		//
		// Compléter donnerait une liste dont l'ordre dépendrait de deux sources,
		// et un serveur retiré de l'environnement resterait joignable par le
		// fichier — donc une configuration dont on ne peut plus rien retirer.
		cfg.Servers = servers
	}
	if v := strings.TrimSpace(os.Getenv(EnvEnrollKey)); v != "" {
		cfg.Enrollment.Key = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvEnrollLabel)); v != "" {
		cfg.Enrollment.Label = v
	}
	return nil
}

// ParseServers lit « ip:port » ou « ip:port,ip:port ».
//
// Le port est facultatif et vaut DefaultDuckyPort quand il est omis. Les
// adresses IPv6 littérales ne sont pas gérées : le champ attend une adresse ou
// un nom d'hôte, et « ::1:6666 » serait ambigu de toute façon.
func ParseServers(raw string) ([]ServerConfig, error) {
	var servers []ServerConfig
	for _, part := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}
		host, portText, found := strings.Cut(entry, ":")
		host = strings.TrimSpace(host)
		if host == "" {
			return nil, fmt.Errorf("adresse vide dans %q", entry)
		}
		port := DefaultDuckyPort
		if found {
			parsed, err := strconv.Atoi(strings.TrimSpace(portText))
			if err != nil || parsed < 1 || parsed > 65535 {
				return nil, fmt.Errorf("port invalide dans %q", entry)
			}
			port = parsed
		}
		servers = append(servers, ServerConfig{IP: host, Port: port})
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("aucune adresse exploitable")
	}
	return servers, nil
}
