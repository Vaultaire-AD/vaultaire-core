// Package config lit la configuration du proxy.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config est le fichier de configuration du proxy.
//
// # Ce qu'il contient, et ce qu'il ne contient PAS
//
// Il porte l'adresse du core, la clé publique du serveur et la CLÉ
// D'ENRÔLEMENT. Il ne porte NI identifiant machine NI clé privée : ces deux-là
// sont produits par le proxy lui-même au premier démarrage et vivent dans le
// fichier d'identité, que personne n'édite à la main.
//
// C'est ce qui permet de déployer le même fichier de configuration sur plusieurs
// hôtes : chacun s'enrôlera et obtiendra sa propre identité.
type Config struct {
	CoreAddress string `yaml:"core_address"`

	Enrollment struct {
		Key   string `yaml:"key"`
		Label string `yaml:"label"`
	} `yaml:"enrollment"`

	// ServerPubKey accepte la clé en clair ou un chemin de fichier.
	ServerPubKey string `yaml:"server_pub_key"`

	// IdentityPath : où le proxy range son identité après enrôlement.
	IdentityPath string `yaml:"identity_path"`

	Proxy struct {
		Version      string   `yaml:"version"`
		Endpoint     string   `yaml:"endpoint"`
		Capabilities []string `yaml:"capabilities"`
	} `yaml:"proxy"`

	LDAPListen  string `yaml:"ldap_listen"`
	DuckyListen string `yaml:"ducky_listen"`
}

// Load lit et valide la configuration.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("lecture de %s : %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("configuration illisible : %w", err)
	}

	// La clé publique du serveur peut être donnée en clair ou par chemin :
	// coller un PEM multiligne dans du YAML est une source d'erreurs
	// d'indentation, et pointer un fichier évite ce piège.
	if resolved, err := resolveMaybePath(cfg.ServerPubKey); err == nil {
		cfg.ServerPubKey = resolved
	} else {
		return Config{}, err
	}

	if cfg.CoreAddress == "" {
		return Config{}, fmt.Errorf("core_address requis")
	}
	if strings.TrimSpace(cfg.ServerPubKey) == "" {
		return Config{}, fmt.Errorf("server_pub_key requis")
	}
	if cfg.IdentityPath == "" {
		cfg.IdentityPath = "/var/lib/vaultaire_proxy/identity.json"
	}
	if cfg.Proxy.Version == "" {
		cfg.Proxy.Version = "1.0.0"
	}
	return cfg, nil
}

// resolveMaybePath rend la valeur telle quelle, ou le contenu du fichier qu'elle
// désigne.
func resolveMaybePath(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.Contains(trimmed, "-----BEGIN") {
		return value, nil
	}
	if !filepath.IsAbs(trimmed) && !strings.HasPrefix(trimmed, "./") {
		return value, nil
	}
	content, err := os.ReadFile(trimmed)
	if err != nil {
		return "", fmt.Errorf("lecture de la clé publique %s : %w", trimmed, err)
	}
	return string(content), nil
}
