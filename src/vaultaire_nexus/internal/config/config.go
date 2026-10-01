// Package config lit la configuration YAML de Vaultaire Nexus.
//
// Toute valeur a un défaut raisonnable : un fichier réduit à « data_dir » suffit
// pour démarrer en mode local. Validate refuse ce qui ne peut pas fonctionner
// AVANT l'ouverture du moindre port, avec un message qui dit quoi corriger.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Modes d'authentification.
const (
	AuthLocal = "local" // seul le compte administrateur local
	AuthLDAP  = "ldap"  // comptes Vaultaire par LDAP(S), plus le compte local s'il est activé
	AuthDucky = "ducky" // comptes Vaultaire par le réseau Ducky (trame 08_01, second facteur compris)
)

// Rôles côté Nexus. Du moins au plus privilégié.
const (
	RoleReader    = "reader"
	RolePublisher = "publisher"
	RoleAdmin     = "admin"
)

// Types de dépôts.
const (
	RepoRPM       = "rpm"
	RepoDeb       = "deb"
	RepoDocker    = "docker"
	RepoVaultaire = "vaultaire"
	RepoGeneric   = "generic"
)

// Config est la racine du fichier.
type Config struct {
	Listen      string `yaml:"listen"`
	PublicURL   string `yaml:"public_url"`
	DataDir     string `yaml:"data_dir"`
	LogPath     string `yaml:"log_path"`
	Debug       bool   `yaml:"debug"`
	MaxUploadMB int64  `yaml:"max_upload_mb"`

	TLS          TLSConfig          `yaml:"tls"`
	Auth         AuthConfig         `yaml:"auth"`
	Usage        UsageConfig        `yaml:"usage"`
	Signing      SigningConfig      `yaml:"signing"`
	Repositories []RepoConfig       `yaml:"repositories"`
	Ducky        DuckyConfig        `yaml:"ducky"`
	Proxy        TrustedProxyConfig `yaml:"trusted_proxies"`
}

// TLSConfig : le registre Docker exige TLS, sauf déclaration « insecure » côté
// démon. self_signed produit un certificat au premier démarrage.
type TLSConfig struct {
	Enable     bool     `yaml:"enable"`
	CertFile   string   `yaml:"cert_file"`
	KeyFile    string   `yaml:"key_file"`
	SelfSigned bool     `yaml:"self_signed"`
	DNSNames   []string `yaml:"dns_names"`
	IPs        []string `yaml:"ip_addresses"`
}

// AuthConfig décrit d'où viennent les comptes et ce qu'ils ont le droit de faire.
type AuthConfig struct {
	Mode           string          `yaml:"mode"`
	SessionMinutes int             `yaml:"session_minutes"`
	LocalAdmin     LocalAdmin      `yaml:"local_admin"`
	LDAP           LDAPConfig      `yaml:"ldap"`
	Roles          RoleMapping     `yaml:"roles"`
	Lockout        LockoutSettings `yaml:"lockout"`
	Ducky          DuckyAuthConfig `yaml:"ducky"`
}

// DuckyAuthConfig règle l'authentification par le réseau Ducky.
type DuckyAuthConfig struct {
	// FallbackLDAP : si le core ne répond pas par Ducky, essayer LDAP (la
	// section auth.ldap doit alors être renseignée). Le repli ne porte pas le
	// second facteur.
	FallbackLDAP bool `yaml:"fallback_ldap"`
	// RequireRight : seules les clés RBAC du core (read:nexus, write:nexus,
	// write:nexus_admin) donnent un rôle ; auth.roles est ignorée. Vaut aussi
	// pour le repli LDAP.
	RequireRight bool `yaml:"require_right"`
	// TimeoutSeconds : attente d'une réponse 08_02 / 08_03.
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// LocalAdmin est le compte de secours, indépendant de Vaultaire.
//
// Mot de passe vide : un mot de passe aléatoire est généré au premier
// démarrage et écrit UNE fois dans <data_dir>/admin.initial (0600).
type LocalAdmin struct {
	Enable   bool   `yaml:"enable"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// LDAPConfig : raccordement à l'annuaire du core.
type LDAPConfig struct {
	URL                string `yaml:"url"`
	BaseDN             string `yaml:"base_dn"`
	BindDN             string `yaml:"bind_dn"`
	BindPassword       string `yaml:"bind_password"`
	UserFilter         string `yaml:"user_filter"`
	CAFile             string `yaml:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	TimeoutSeconds     int    `yaml:"timeout_seconds"`
}

// RoleMapping : groupes Vaultaire → rôle Nexus. « * » = tout compte authentifié.
type RoleMapping struct {
	Admin     []string `yaml:"admin"`
	Publisher []string `yaml:"publisher"`
	Reader    []string `yaml:"reader"`
}

// LockoutSettings borne les essais de mot de passe par compte et par adresse.
type LockoutSettings struct {
	MaxFailures   int `yaml:"max_failures"`
	WindowMinutes int `yaml:"window_minutes"`
}

// UsageConfig : suivi des téléchargements.
type UsageConfig struct {
	RetentionDays int  `yaml:"retention_days"`
	Anonymize     bool `yaml:"anonymize_ip"`
}

// SigningConfig : signature GPG des métadonnées APT et YUM.
//
// Sans clé, les dépôts sont servis non signés : apt exige alors
// « [trusted=yes] » et dnf « gpgcheck=0 ». La signature passe par le binaire
// gpg de l'hôte : aucune bibliothèque OpenPGP maison.
type SigningConfig struct {
	Enable    bool   `yaml:"enable"`
	GPGHome   string `yaml:"gpg_home"`
	KeyID     string `yaml:"key_id"`
	GPGBinary string `yaml:"gpg_binary"`
}

// RepoConfig : dépôts créés au démarrage s'ils n'existent pas encore.
// Ceux créés depuis l'interface vivent dans les métadonnées, pas ici.
type RepoConfig struct {
	Name         string   `yaml:"name"`
	Type         string   `yaml:"type"`
	Description  string   `yaml:"description"`
	Public       bool     `yaml:"public"`
	KeepVersions int      `yaml:"keep_versions"`
	Distribution string   `yaml:"distribution"`
	Component    string   `yaml:"component"`
	Readers      []string `yaml:"readers"`
	Publishers   []string `yaml:"publishers"`
}

// DuckyConfig : raccordement au cluster Vaultaire. DÉSACTIVÉ par défaut —
// le core ne connaît pas encore le type « vaultaire_nexus » (CORE_CHANGEMENTS.md).
type DuckyConfig struct {
	Enable     bool   `yaml:"enable"`
	ConfigPath string `yaml:"config"`
	KeyPath    string `yaml:"keys"`
	Enroll     bool   `yaml:"enroll"`
}

// TrustedProxyConfig : adresses dont on accepte X-Forwarded-For.
type TrustedProxyConfig struct {
	CIDRs []string `yaml:"cidrs"`
}

var nomDepot = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidRepoName est la règle unique de nommage d'un dépôt : il apparaît dans
// des chemins de fichiers et des URL.
func ValidRepoName(n string) bool { return nomDepot.MatchString(n) }

// ValidRepoType dit si un type est connu.
func ValidRepoType(t string) bool {
	switch t {
	case RepoRPM, RepoDeb, RepoDocker, RepoVaultaire, RepoGeneric:
		return true
	}
	return false
}

// Default rend une configuration utilisable telle quelle en mode local.
func Default() Config {
	return Config{
		Listen:      ":8843",
		DataDir:     "/var/lib/vaultaire_nexus",
		LogPath:     "/var/log/vaultaire/",
		MaxUploadMB: 4096,
		TLS:         TLSConfig{Enable: true, SelfSigned: true},
		Auth: AuthConfig{
			Mode:           AuthLocal,
			SessionMinutes: 30,
			LocalAdmin:     LocalAdmin{Enable: true, Username: "admin"},
			LDAP: LDAPConfig{
				UserFilter:     "(uid=%s)",
				TimeoutSeconds: 10,
			},
			Roles: RoleMapping{
				Admin:  []string{"vaultaire"},
				Reader: []string{"*"},
			},
			Lockout: LockoutSettings{MaxFailures: 5, WindowMinutes: 15},
		},
		Usage: UsageConfig{RetentionDays: 90},
		Signing: SigningConfig{
			GPGBinary: "gpg",
		},
		Ducky: DuckyConfig{
			ConfigPath: "/etc/vaultaire_nexus/ducky.yaml",
			// KeyPath vide : <data_dir>/ducky, résolu après lecture (l'identité
			// est ÉCRITE à l'enrôlement, /etc n'est pas le bon endroit).
			Enroll: true,
		},
	}
}

// Load lit le fichier par-dessus les défauts, puis l'environnement.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("lecture de %s : %w", path, err)
		}
		// Strict : un champ inconnu est une faute de frappe, et l'ignorer
		// laisserait tourner Nexus avec un réglage qu'on croit posé.
		// KnownFields est l'équivalent v3 de l'UnmarshalStrict de v2 ; un
		// fichier vide rend io.EOF, qui n'est pas une erreur — les défauts
		// s'appliquent, comme avant.
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
			return cfg, fmt.Errorf("%s : %w", path, err)
		}
	}
	applyEnv(&cfg)
	if cfg.Ducky.KeyPath == "" && cfg.DataDir != "" {
		cfg.Ducky.KeyPath = filepath.Join(cfg.DataDir, "ducky")
	}
	return cfg, cfg.Validate()
}

// applyEnv : les secrets peuvent venir de l'environnement pour rester hors des
// fichiers — c'est la forme attendue en conteneur.
func applyEnv(c *Config) {
	if v := os.Getenv("NEXUS_ADMIN_PASSWORD"); v != "" {
		c.Auth.LocalAdmin.Password = v
	}
	if v := os.Getenv("NEXUS_LDAP_BIND_PASSWORD"); v != "" {
		c.Auth.LDAP.BindPassword = v
	}
	if v := os.Getenv("NEXUS_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("NEXUS_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("NEXUS_PUBLIC_URL"); v != "" {
		c.PublicURL = v
	}
}

// Validate refuse les configurations qui ne peuvent pas marcher.
func (c *Config) Validate() error {
	var errs []string
	if c.DataDir == "" {
		errs = append(errs, "data_dir est obligatoire")
	} else if !filepath.IsAbs(c.DataDir) {
		errs = append(errs, "data_dir doit être un chemin absolu")
	}
	if c.MaxUploadMB <= 0 {
		errs = append(errs, "max_upload_mb doit être positif")
	}
	if c.Ducky.Enable && c.PublicURL == "" {
		errs = append(errs, "ducky.enable exige public_url : c'est l'adresse annoncée au cluster")
	}
	if c.TLS.Enable && !c.TLS.SelfSigned && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		errs = append(errs, "tls : cert_file et key_file, ou self_signed: true")
	}
	switch c.Auth.Mode {
	case AuthLocal:
		if !c.Auth.LocalAdmin.Enable {
			errs = append(errs, "auth.mode local sans local_admin.enable : personne ne pourrait se connecter")
		}
	case AuthLDAP:
		if c.Auth.LDAP.URL == "" || c.Auth.LDAP.BaseDN == "" {
			errs = append(errs, "auth.mode ldap : ldap.url et ldap.base_dn sont obligatoires")
		}
		if !strings.Contains(c.Auth.LDAP.UserFilter, "%s") {
			errs = append(errs, "auth.ldap.user_filter doit contenir %s")
		}
	case AuthDucky:
		if !c.Ducky.Enable {
			errs = append(errs, "auth.mode ducky exige ducky.enable: true (la vérification passe par le cluster)")
		}
		if c.Auth.Ducky.FallbackLDAP && (c.Auth.LDAP.URL == "" || c.Auth.LDAP.BaseDN == "") {
			errs = append(errs, "auth.ducky.fallback_ldap : ldap.url et ldap.base_dn sont obligatoires")
		}
	default:
		errs = append(errs, fmt.Sprintf("auth.mode inconnu : %q (local, ldap, ducky)", c.Auth.Mode))
	}
	if c.Auth.Ducky.TimeoutSeconds <= 0 {
		c.Auth.Ducky.TimeoutSeconds = 7
	}
	if c.Auth.LocalAdmin.Enable && c.Auth.LocalAdmin.Username == "" {
		errs = append(errs, "auth.local_admin.username est vide")
	}
	if c.Auth.SessionMinutes <= 0 {
		c.Auth.SessionMinutes = 30
	}
	if c.Auth.Lockout.MaxFailures <= 0 {
		c.Auth.Lockout.MaxFailures = 5
	}
	if c.Auth.Lockout.WindowMinutes <= 0 {
		c.Auth.Lockout.WindowMinutes = 15
	}
	if c.Usage.RetentionDays <= 0 {
		c.Usage.RetentionDays = 90
	}
	if c.Signing.Enable && c.Signing.KeyID == "" {
		errs = append(errs, "signing.enable sans signing.key_id")
	}
	seen := map[string]bool{}
	for _, r := range c.Repositories {
		if !ValidRepoName(r.Name) {
			errs = append(errs, fmt.Sprintf("dépôt %q : nom invalide (a-z, 0-9, . _ -)", r.Name))
		}
		if !ValidRepoType(r.Type) {
			errs = append(errs, fmt.Sprintf("dépôt %q : type %q inconnu (rpm, deb, docker, vaultaire, generic)", r.Name, r.Type))
		}
		if seen[r.Name] {
			errs = append(errs, fmt.Sprintf("dépôt %q déclaré deux fois", r.Name))
		}
		seen[r.Name] = true
	}
	if len(errs) > 0 {
		return fmt.Errorf("configuration invalide :\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// SessionTTL rend la durée d'une session web.
func (c *Config) SessionTTL() time.Duration {
	return time.Duration(c.Auth.SessionMinutes) * time.Minute
}

// MaxUploadBytes rend la taille maximale d'un envoi.
func (c *Config) MaxUploadBytes() int64 { return c.MaxUploadMB << 20 }
