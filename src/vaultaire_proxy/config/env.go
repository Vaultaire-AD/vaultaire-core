package config

import "os"

// Variables d'environnement reconnues.
//
// Elles l'emportent sur le fichier, et c'est le bon sens de la priorité : en
// conteneur, le fichier est une image figée alors que l'environnement est ce
// qu'on ajuste au déploiement. L'inverse obligerait à reconstruire pour changer
// d'adresse de core.
const (
	EnvCoreAddress   = "VAULTAIRE_IP_CORE"
	EnvEnrollmentKey = "VAULTAIRE_ENROLL_KEY"
	EnvKeyDir        = "VAULTAIRE_KEY_DIR"
	EnvEndpoint      = "VAULTAIRE_PROXY_ENDPOINT"
	EnvLabel         = "VAULTAIRE_PROXY_LABEL"
)

// applyEnv superpose l'environnement au fichier.
//
// # Pourquoi la clé d'enrôlement surtout
//
// C'est le seul secret de la configuration. Le passer par l'environnement
// permet de le tenir hors du dépôt et hors de l'image : un fichier
// config.yaml contenant une clé valide finit toujours par être commité.
func applyEnv(cfg *Config) {
	if v := os.Getenv(EnvCoreAddress); v != "" {
		cfg.CoreAddress = v
	}
	if v := os.Getenv(EnvEnrollmentKey); v != "" {
		cfg.Enrollment.Key = v
	}
	if v := os.Getenv(EnvKeyDir); v != "" {
		cfg.KeyDir = v
	}
	if v := os.Getenv(EnvEndpoint); v != "" {
		cfg.Proxy.Endpoint = v
	}
	if v := os.Getenv(EnvLabel); v != "" {
		cfg.Enrollment.Label = v
	}
}
