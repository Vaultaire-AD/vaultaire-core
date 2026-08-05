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
// Il porte l'adresse du core, éventuellement la clé publique du serveur, et la
// CLÉ D'ENRÔLEMENT. Il ne porte NI identifiant machine NI clé privée : ces deux
// -là sont produits par le proxy lui-même au premier démarrage et vivent dans
// key_dir, que personne n'édite à la main.
//
// C'est ce qui permet de déployer le MÊME fichier sur plusieurs hôtes : chacun
// s'enrôle et obtient sa propre identité.
type Config struct {
	CoreAddress string `yaml:"core_address"`

	Enrollment struct {
		Key   string `yaml:"key"`
		Label string `yaml:"label"`
	} `yaml:"enrollment"`

	// ServerPubKey accepte la clé en clair ou un chemin de fichier.
	//
	// Facultative : sans elle, le proxy la demande au core au démarrage
	// (« askkey »). Cet échange est en clair et se prête donc à une substitution
	// par un intermédiaire actif. La renseigner est le choix sûr dès que le
	// réseau entre le proxy et le core n'est pas de confiance.
	ServerPubKey string `yaml:"server_pub_key"`

	// KeyDir range la paire de clés, la clé du core et l'identité.
	//
	// DOIT survivre aux redémarrages. Un conteneur sans volume persistant se
	// réenrôle à chaque lancement et épuise le quota de la clé d'enrôlement.
	KeyDir string `yaml:"key_dir"`

	// AllowReEnroll autorise le proxy à se réenrôler seul si le core refuse son
	// identité. Voir main.go pour ce que cela implique.
	AllowReEnroll bool `yaml:"allow_re_enroll"`

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
	var cfg Config

	// Un fichier absent n'est pas une erreur SI l'environnement porte le
	// nécessaire : c'est le mode de déploiement en conteneur, où tout passe par
	// des variables et où monter un fichier n'aurait rien à contenir.
	//
	// Les autres erreurs de lecture — droits, fichier illisible — restent
	// fatales : elles signalent un problème de déploiement, pas une intention.
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return Config{}, fmt.Errorf("configuration illisible : %w", err)
		}
	case !os.IsNotExist(err):
		return Config{}, fmt.Errorf("lecture de %s : %w", path, err)
	}

	// L'environnement se superpose AVANT la validation : une valeur fournie par
	// variable doit satisfaire les mêmes contrôles qu'une valeur du fichier, et
	// une adresse de core vide reste une erreur d'où qu'elle vienne.
	applyEnv(&cfg)

	// La clé publique peut être donnée en clair ou par chemin : coller un PEM
	// multiligne dans du YAML est une source d'erreurs d'indentation, et
	// pointer un fichier évite ce piège.
	resolved, err := resolveMaybePath(cfg.ServerPubKey)
	if err != nil {
		return Config{}, err
	}
	cfg.ServerPubKey = resolved

	if strings.TrimSpace(cfg.CoreAddress) == "" {
		return Config{}, fmt.Errorf("core_address requis")
	}
	if strings.TrimSpace(cfg.KeyDir) == "" {
		cfg.KeyDir = "/var/lib/vaultaire_proxy/keys"
	}
	if strings.TrimSpace(cfg.Proxy.Version) == "" {
		cfg.Proxy.Version = "1.0.0"
	}
	if strings.TrimSpace(cfg.Proxy.Endpoint) == "" {
		// Sans endpoint, le core enregistrerait un service qu'on ne sait pas
		// joindre : la ligne du cluster serait décorative.
		return Config{}, fmt.Errorf("proxy.endpoint requis : adresse à laquelle ce proxy est joignable")
	}
	if strings.TrimSpace(cfg.Enrollment.Label) == "" {
		cfg.Enrollment.Label = "vaultaire_proxy"
	}
	return cfg, nil
}

// resolveMaybePath rend la valeur telle quelle, ou le contenu du fichier désigné.
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
