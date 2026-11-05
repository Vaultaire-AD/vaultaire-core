package configuration_file

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"vaultaire/core/auth/ratelimit"
	"vaultaire/core/storage"
)

// La configuration par variables d'environnement — 2.3, image rootless.
//
// # Pourquoi
//
// Un core déployé en conteneur (Docker, Kubernetes) reçoit ses secrets par
// l'environnement ou par des fichiers montés, depuis le gestionnaire de secrets
// de la plateforme : un Secret Kubernetes, Vault, External Secrets, SOPS. Le
// fichier serveur_conf.yaml, lui, est une ConfigMap — versionnée dans le dépôt
// GitOps, donc lisible par qui lit le dépôt. Il ne doit porter AUCUN secret.
//
// Chaque variable l'emporte sur la clé du fichier qui lui correspond. Une
// variable absente laisse le fichier décider ; une variable POSÉE mais vide
// est une erreur — c'est presque toujours une clé de Secret mal nommée, et la
// laisser passer ferait démarrer le core avec la valeur du fichier sans que
// personne ne le voie.
//
// # Les variantes _FILE
//
// Pour chaque secret, NOM_FILE désigne un fichier dont le contenu est la
// valeur (une seule ligne, la fin de ligne est retirée). C'est la convention
// des images officielles (MariaDB, Postgres) et des secrets Docker/Kubernetes
// montés en volume : la valeur n'apparaît alors ni dans `docker inspect`, ni
// dans /proc/<pid>/environ. Poser NOM et NOM_FILE à la fois est refusé.

// variableEnv décrit une variable reconnue.
type variableEnv struct {
	Nom     string
	Secret  bool   // accepte la variante _FILE
	Aide    string // ce qu'elle remplace, pour la documentation et les erreurs
	Poser   func(valeur string) error
	Exemple string
}

// VariablesEnvironnement est la table complète, dans l'ordre de la
// documentation (docs/Installation/Kubernetes.md).
func VariablesEnvironnement() []variableEnv {
	texte := func(cible *string) func(string) error {
		return func(v string) error { *cible = v; return nil }
	}
	entier := func(cible *int, nom string) func(string) error {
		return func(v string) error {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("%s : port attendu entre 1 et 65535, reçu %q", nom, v)
			}
			*cible = n
			return nil
		}
	}
	booleen := func(cible *bool, nom string) func(string) error {
		return func(v string) error {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("%s : true ou false attendu, reçu %q", nom, v)
			}
			*cible = b
			return nil
		}
	}
	liste := func(cible *[]string) func(string) error {
		return func(v string) error { *cible = decouperListe(v); return nil }
	}
	repertoire := func(cible *string) func(string) error {
		return func(v string) error {
			if !strings.HasSuffix(v, "/") {
				v += "/"
			}
			*cible = v
			return nil
		}
	}

	return []variableEnv{
		// Base de données
		{Nom: "VAULTAIRE_DB_HOST", Aide: "database.ip_database", Poser: texte(&storage.Database_iPDatabase), Exemple: "mariadb.vaultaire.svc"},
		{Nom: "VAULTAIRE_DB_PORT", Aide: "database.port_database", Exemple: "3306",
			Poser: func(v string) error {
				var n int
				if err := entier(&n, "VAULTAIRE_DB_PORT")(v); err != nil {
					return err
				}
				storage.Database_portDatabase = strconv.Itoa(n)
				return nil
			}},
		{Nom: "VAULTAIRE_DB_NAME", Aide: "database.databaseName", Poser: texte(&storage.Database_databaseName), Exemple: "vaultaire"},
		{Nom: "VAULTAIRE_DB_USERNAME", Secret: true, Aide: "database.username", Poser: texte(&storage.Database_username), Exemple: "vaultaire"},
		{Nom: "VAULTAIRE_DB_PASSWORD", Secret: true, Aide: "database.password", Poser: texte(&storage.Database_password)},

		// Compte d'amorçage
		{Nom: "VAULTAIRE_ADMIN_USERNAME", Secret: true, Aide: "administrateur.username", Poser: texte(&storage.Administrateur_Username), Exemple: "admin"},
		{Nom: "VAULTAIRE_ADMIN_PASSWORD", Secret: true, Aide: "administrateur.password", Poser: texte(&storage.Administrateur_Password)},
		{Nom: "VAULTAIRE_ADMIN_PUBLIC_KEY", Secret: true, Aide: "administrateur.public_key", Poser: texte(&storage.Administrateur_PublicKey), Exemple: "ssh-ed25519 AAAA…"},

		// Ports d'écoute
		{Nom: "VAULTAIRE_DUCKY_PORT", Aide: "serveurlistenport", Exemple: "6666",
			Poser: func(v string) error {
				var n int
				if err := entier(&n, "VAULTAIRE_DUCKY_PORT")(v); err != nil {
					return err
				}
				storage.ServeurLisetenPort = strconv.Itoa(n)
				return nil
			}},
		{Nom: "VAULTAIRE_LDAP_PORT", Aide: "ldap.ldap_port", Poser: entier(&storage.Ldap_Port, "VAULTAIRE_LDAP_PORT"), Exemple: "3389"},
		{Nom: "VAULTAIRE_LDAPS_PORT", Aide: "ldap.ldaps_port", Poser: entier(&storage.Ldaps_Port, "VAULTAIRE_LDAPS_PORT"), Exemple: "3636"},
		{Nom: "VAULTAIRE_WEB_PORT", Aide: "website.website_port", Poser: entier(&storage.Website_Port, "VAULTAIRE_WEB_PORT"), Exemple: "4443"},
		{Nom: "VAULTAIRE_API_PORT", Aide: "api.api_port", Poser: entier(&storage.API_Port, "VAULTAIRE_API_PORT"), Exemple: "6643"},
		{Nom: "VAULTAIRE_DNS_PORT", Aide: "dns.dns_port", Poser: entier(&storage.Dns_Port, "VAULTAIRE_DNS_PORT"), Exemple: "5353"},
		{Nom: "VAULTAIRE_DNS_ENABLE", Aide: "dns.dns_enable", Poser: booleen(&storage.Dns_Enable, "VAULTAIRE_DNS_ENABLE"), Exemple: "false"},

		// Certificats : noms à couvrir (listes séparées par des virgules)
		{Nom: "VAULTAIRE_LDAPS_TLS_DNS_NAMES", Aide: "ldap.ldaps_tls_dns_names", Poser: liste(&storage.Ldaps_TLS_DNSNames), Exemple: "ldap.acme.lan,vaultaire-ldap"},
		{Nom: "VAULTAIRE_LDAPS_TLS_IP_ADDRESSES", Aide: "ldap.ldaps_tls_ip_addresses", Poser: liste(&storage.Ldaps_TLS_IPs), Exemple: "10.0.0.10"},
		{Nom: "VAULTAIRE_WEB_TLS_DNS_NAMES", Aide: "website.web_tls_dns_names", Poser: liste(&storage.Web_TLS_DNSNames), Exemple: "sso.acme.lan"},
		{Nom: "VAULTAIRE_WEB_TLS_IP_ADDRESSES", Aide: "website.web_tls_ip_addresses", Poser: liste(&storage.Web_TLS_IPs), Exemple: "10.0.0.10"},
		// Certificats importés (TO-DO 262) : chemins, pas secrets — la clé
		// elle-même reste dans son fichier, relu à chaud.
		{Nom: "VAULTAIRE_LDAPS_TLS_CERT_FILE", Aide: "ldap.ldaps_tls_cert_file", Poser: texte(&storage.Ldaps_TLS_CertFile), Exemple: "/run/secrets/vaultaire-tls/ldaps/tls.crt"},
		{Nom: "VAULTAIRE_LDAPS_TLS_KEY_FILE", Aide: "ldap.ldaps_tls_key_file", Poser: texte(&storage.Ldaps_TLS_KeyFile), Exemple: "/run/secrets/vaultaire-tls/ldaps/tls.key"},
		{Nom: "VAULTAIRE_WEB_TLS_CERT_FILE", Aide: "website.web_tls_cert_file", Poser: texte(&storage.Web_TLS_CertFile), Exemple: "/run/secrets/vaultaire-tls/web/tls.crt"},
		{Nom: "VAULTAIRE_WEB_TLS_KEY_FILE", Aide: "website.web_tls_key_file", Poser: texte(&storage.Web_TLS_KeyFile), Exemple: "/run/secrets/vaultaire-tls/web/tls.key"},
		{Nom: "VAULTAIRE_API_TLS_CERT_FILE", Aide: "api.api_tls_cert_file", Poser: texte(&storage.API_TLS_CertFile), Exemple: "/run/secrets/vaultaire-tls/api/tls.crt"},
		{Nom: "VAULTAIRE_API_TLS_KEY_FILE", Aide: "api.api_tls_key_file", Poser: texte(&storage.API_TLS_KeyFile), Exemple: "/run/secrets/vaultaire-tls/api/tls.key"},
		{Nom: "VAULTAIRE_WEB_TRUSTED_PROXIES", Aide: "website.web_trusted_proxies", Exemple: "10.42.0.0/16",
			Poser: func(v string) error {
				storage.Web_Trusted_Proxies = decouperListe(v)
				ratelimit.ProxiesDeConfiance = storage.Web_Trusted_Proxies
				return nil
			}},

		// Répertoires
		{Nom: "VAULTAIRE_DATA_DIR", Aide: "file-path.clientconfpath", Poser: repertoire(&storage.Client_Conf_path), Exemple: "/var/lib/vaultaire/"},
		{Nom: "VAULTAIRE_LOG_DIR", Aide: "file-path.logpath", Poser: repertoire(&storage.LogPath), Exemple: "/var/log/vaultaire/"},
		{Nom: "VAULTAIRE_SOCKET", Aide: "file-path.socketpath", Poser: texte(&storage.SocketPath), Exemple: "/run/vaultaire/vaultaire.sock"},
		{Nom: "VAULTAIRE_SCRIPTS_DIR", Aide: "automatisation.sh_folder_path", Poser: repertoire(&storage.Sh_folder_path), Exemple: "/opt/vaultaire/automatisation/"},
		{Nom: "VAULTAIRE_AGENT_PACKAGE_DIR", Aide: "automatisation.agent_package_path", Poser: repertoire(&storage.Agent_Package_path), Exemple: "/opt/vaultaire/vaultaire_client/"},

		// Journal
		{Nom: "VAULTAIRE_DEBUG", Aide: "debug.debug", Poser: booleen(&storage.Debug, "VAULTAIRE_DEBUG"), Exemple: "false"},
	}
}

// AppliquerEnvironnement pose les valeurs lues dans l'environnement.
//
// lire est os.LookupEnv en production, une table dans les tests.
func AppliquerEnvironnement(lire func(string) (string, bool)) error {
	var erreurs []string
	for _, v := range VariablesEnvironnement() {
		valeur, posee, err := lireVariable(v, lire)
		if err != nil {
			erreurs = append(erreurs, err.Error())
			continue
		}
		if !posee {
			continue
		}
		if err := v.Poser(valeur); err != nil {
			erreurs = append(erreurs, err.Error())
		}
	}
	if len(erreurs) > 0 {
		sort.Strings(erreurs)
		return fmt.Errorf("variables d'environnement refusées :\n  - %s", strings.Join(erreurs, "\n  - "))
	}
	return nil
}

// lireVariable rend la valeur de NOM, ou le contenu du fichier NOM_FILE.
func lireVariable(v variableEnv, lire func(string) (string, bool)) (string, bool, error) {
	valeur, direct := lire(v.Nom)
	chemin, parFichier := "", false
	if v.Secret {
		chemin, parFichier = lire(v.Nom + "_FILE")
	}
	switch {
	case direct && parFichier:
		return "", false, fmt.Errorf("%s et %s_FILE sont posées toutes les deux : n'en garder qu'une", v.Nom, v.Nom)
	case parFichier:
		if strings.TrimSpace(chemin) == "" {
			return "", false, fmt.Errorf("%s_FILE est posée mais vide", v.Nom)
		}
		contenu, err := lireFichierSecret(chemin)
		if err != nil {
			return "", false, fmt.Errorf("%s_FILE : lecture de %s impossible : %v", v.Nom, chemin, err)
		}
		valeur = strings.TrimRight(string(contenu), "\r\n")
		if valeur == "" {
			return "", false, fmt.Errorf("%s_FILE : le fichier %s est vide", v.Nom, chemin)
		}
		return valeur, true, nil
	case direct:
		if strings.TrimSpace(valeur) == "" {
			// Une clé de Secret mal nommée rend une variable vide : la laisser
			// passer ferait démarrer le core sur la valeur du fichier, en
			// silence.
			return "", false, fmt.Errorf("%s est posée mais vide", v.Nom)
		}
		return valeur, true, nil
	}
	return "", false, nil
}

// decouperListe lit « a, b,c » ; une liste vide (« , ») rend nil.
func decouperListe(v string) []string {
	var sortie []string
	for _, e := range strings.Split(v, ",") {
		if e = strings.TrimSpace(e); e != "" {
			sortie = append(sortie, e)
		}
	}
	return sortie
}

// TailleMaxSecret borne la lecture d'un fichier de secret : un mot de passe,
// une clé publique. Un chemin qui désignerait autre chose (un journal, un
// périphérique) n'est pas lu en entier en mémoire.
const TailleMaxSecret = 64 << 10

// lireFichierSecret lit un fichier de secret par un os.Root ouvert sur son
// répertoire : le nom ne peut pas en sortir (gosec G304 — le chemin vient de
// l'environnement, que seul l'exploitant pose, mais la garantie ne coûte rien).
func lireFichierSecret(chemin string) ([]byte, error) {
	racine, err := os.OpenRoot(filepath.Dir(chemin))
	if err != nil {
		return nil, err
	}
	defer func() { _ = racine.Close() }()
	f, err := racine.Open(filepath.Base(chemin))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	contenu, err := io.ReadAll(io.LimitReader(f, TailleMaxSecret+1))
	if err != nil {
		return nil, err
	}
	if len(contenu) > TailleMaxSecret {
		return nil, fmt.Errorf("plus de %d octets : ce n'est pas un fichier de secret", TailleMaxSecret)
	}
	return contenu, nil
}
