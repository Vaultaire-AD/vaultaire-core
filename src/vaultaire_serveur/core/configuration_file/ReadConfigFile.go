package configuration_file

import (
	"fmt"
	"os"
	"sort"
	"vaultaire/core/auth/ratelimit"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/storage"

	yaml "gopkg.in/yaml.v3"
)

func ReadConfigUser[T any](filePath string) (*T, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeFileConfig, "config: read file failed: "+err.Error())
		return nil, err
	}

	var config T
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeFileConfig, "config: YAML decode failed: "+err.Error())
		return nil, err
	}

	return &config, nil
}

// ErreurDeValeur : le fichier a été trouvé et lu, mais une valeur qu'il porte
// est refusée.
//
// Un type à part pour que l'appelant ne confonde pas ce cas avec un fichier
// introuvable : le message de `ErreurConfigIntrouvable` propose de recopier le
// fichier de référence, ce qui écraserait une configuration dont une seule
// ligne est à corriger.
type ErreurDeValeur struct {
	Cause error
}

func (e *ErreurDeValeur) Error() string { return e.Cause.Error() }
func (e *ErreurDeValeur) Unwrap() error { return e.Cause }

func LoadConfig(filePath string) error {
	// Le fichier est lu EN ENTIER puis décodé, au lieu d'être décodé au fil de
	// l'ouverture.
	//
	// C'est ce qui permet d'inspecter son TEXTE avant décodage — et il faut
	// l'inspecter : une clé qu'aucune étiquette ne réclame ne laisse aucune
	// trace après décodage, par construction. C'est exactement ce qui a rendu la
	// section « administreur: » invisible pendant toute la vie du produit
	// (TO-DO 99, voir SignalerCleMalOrthographiee).
	contenu, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	if err := SignalerCleMalOrthographiee(contenu); err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeFileConfig, "config: "+err.Error())
		return err
	}

	// Initialiser une variable pour stocker les données du fichier
	var config storage.Config

	// Décoder le fichier YAML dans la structure Config
	if err := yaml.Unmarshal(contenu, &config); err != nil {
		return err
	}

	// Load configuration with env overrides for sensitive data
	if val := os.Getenv("VAULTAIRE_DB_USERNAME"); val != "" {
		storage.Database_username = val
	} else if config.Database.Database_username != nil {
		storage.Database_username = *config.Database.Database_username
	}

	if val := os.Getenv("VAULTAIRE_DB_PASSWORD"); val != "" {
		storage.Database_password = val
	} else if config.Database.Database_password != nil {
		storage.Database_password = *config.Database.Database_password
	}

	if config.Database.Database_iPDatabase != nil {
		storage.Database_iPDatabase = *config.Database.Database_iPDatabase
	}
	if config.Database.Database_portDatabase != nil {
		storage.Database_portDatabase = *config.Database.Database_portDatabase
	}
	if config.Database.Database_databaseName != nil {
		storage.Database_databaseName = *config.Database.Database_databaseName
	}

	if config.Path.SocketPath != nil {
		storage.SocketPath = *config.Path.SocketPath
	}
	if config.Path.Client_Conf_path != nil {
		storage.Client_Conf_path = *config.Path.Client_Conf_path
	}
	if config.Path.LogPath != nil {
		storage.LogPath = *config.Path.LogPath
	}
	if config.ServerListenPort != nil {
		storage.ServeurLisetenPort = *config.ServerListenPort
	}
	// Les chemins de clés ne sont plus configurés via YAML - toutes les clés sont en BDD
	// Les variables PrivateKeyPath, PublicKeyPath, PrivateKeyforlogintoclient, PublicKeyforlogintoclient
	// restent pour compatibilité avec EnsureLoginClientKeyFiles qui écrit temporairement les fichiers SSH

	if config.Ldap.Ldap_Enable != nil {
		storage.Ldap_Enable = *config.Ldap.Ldap_Enable
	}
	if config.Dns.Dns_Enable != nil {
		storage.Dns_Enable = *config.Dns.Dns_Enable
	}
	if config.Ldap.Ldaps_Enable != nil {
		storage.Ldaps_Enable = *config.Ldap.Ldaps_Enable
	}
	if config.Ldap.Ldap_Port != nil {
		storage.Ldap_Port = *config.Ldap.Ldap_Port
	}
	if config.Ldap.Ldaps_Port != nil {
		storage.Ldaps_Port = *config.Ldap.Ldaps_Port
	}
	// Les SAN sont recopiés même vides : une liste vidée dans le fichier doit
	// pouvoir revenir à la seule détection automatique.
	// Second facteur au bind LDAP : exigé sauf réglage contraire explicite.
	ldapstorage.MFABypass = config.Ldap.Ldap_MFA_Bypass != nil && *config.Ldap.Ldap_MFA_Bypass
	if ldapstorage.MFABypass {
		logs.Write_Log("WARNING", "ldap.mfa_bypass activé : les comptes soumis au second facteur se lient par LDAP sans code")
	}
	// Élargissement des recherches `one` : refusé sauf réglage contraire explicite.
	ldapstorage.OneLevelSubtree = config.Ldap.Ldap_OneLevel_Subtree != nil && *config.Ldap.Ldap_OneLevel_Subtree
	if ldapstorage.OneLevelSubtree {
		logs.Write_Log("WARNING", "ldap.onelevel_subtree activé : TOUTE recherche « one » rend l'arborescence, quel que soit le conteneur")
	}
	// Bind avec mot de passe hors TLS : accepté sauf réglage contraire explicite
	// (TO-DO 152). Le commentaire de la variable disait « à activer une fois
	// vérifié que le parc sait faire du LDAPS » ; rien ne permettait de le faire
	// sans recompiler.
	ldapstorage.RequireTLSForBind = config.Ldap.Ldap_Require_TLS_For_Bind != nil && *config.Ldap.Ldap_Require_TLS_For_Bind
	if ldapstorage.RequireTLSForBind {
		logs.Write_Log("INFO", "ldap.require_tls_for_bind activé : un bind avec mot de passe sur le port en clair est refusé (strongerAuthRequired)")
	}
	// Bornes de recherche et de pagination. Une valeur refusée ARRÊTE le
	// démarrage : voir ldapstorage.AppliquerLimites pour le pourquoi.
	if err := ldapstorage.AppliquerLimites(config.Ldap.Ldap_Limites); err != nil {
		return &ErreurDeValeur{Cause: err}
	}
	if len(config.Ldap.Ldap_Limites) > 0 {
		logs.Write_Log("INFO", "ldap.limites : bornes en vigueur — "+ldapstorage.LimitesEnVigueur())
	}
	storage.Ldaps_TLS_DNSNames = config.Ldap.Ldaps_TLS_DNSNames
	storage.Ldaps_TLS_IPs = config.Ldap.Ldaps_TLS_IPs
	if config.Website.Website_Enable != nil {
		storage.Website_Enable = *config.Website.Website_Enable
	}
	if config.Website.Website_Port != nil {
		storage.Website_Port = *config.Website.Website_Port
	}
	// Mêmes règles que pour les SAN LDAPS : recopiés même vides.
	storage.Web_TLS_DNSNames = config.Website.Web_TLS_DNSNames
	storage.Web_TLS_IPs = config.Website.Web_TLS_IPs
	// Recopié même vide, et pour une raison de sécurité : vider la liste dans le
	// fichier doit ramener à « on ne croit personne ». Ne recopier que les
	// valeurs non vides laisserait un relais de confiance en place après qu'on
	// l'a retiré de la configuration.
	storage.Web_Trusted_Proxies = config.Website.Web_Trusted_Proxies
	ratelimit.ProxiesDeConfiance = config.Website.Web_Trusted_Proxies
	if config.Api.API_Enable != nil {
		storage.API_Enable = *config.Api.API_Enable
	}
	if config.Api.API_Port != nil {
		storage.API_Port = *config.Api.API_Port
	}
	if config.Debug.Debug != nil {
		storage.Debug = *config.Debug.Debug
	}
	if err := appliquerDetail(config.Debug.Detail); err != nil {
		return &ErreurDeValeur{Cause: err}
	}
	// servercheckonlinetimer a quitté le fichier pour la base.
	//
	// Le champ n'est plus lu. Il n'est pas non plus ignoré en silence : une
	// installation qui le porte encore verrait sinon sa valeur sans effet, et
	// chercherait la panne du côté de la boucle. Le message nomme le
	// remplacement.
	if config.Path.ServerCheckOnlineTimerObsolete != nil {
		logs.Write_Log("WARNING",
			"config: « servercheckonlinetimer » n'est plus lu. La cadence de "+
				"vérification des machines vit en base : « vlt settings set "+
				"check_online_minutes <valeur> ». Retirez la ligne du fichier.")
	}

	// Administrateur settings
	if config.Administrateur.Enable != nil {
		storage.Administrateur_Enable = *config.Administrateur.Enable
	}

	if val := os.Getenv("VAULTAIRE_ADMIN_USERNAME"); val != "" {
		storage.Administrateur_Username = val
	} else if config.Administrateur.Username != nil {
		storage.Administrateur_Username = *config.Administrateur.Username
	}

	if val := os.Getenv("VAULTAIRE_ADMIN_PASSWORD"); val != "" {
		storage.Administrateur_Password = val
	} else if config.Administrateur.Password != nil {
		storage.Administrateur_Password = *config.Administrateur.Password
	}

	if config.Administrateur.PublicKey != nil {
		storage.Administrateur_PublicKey = *config.Administrateur.PublicKey
	}

	// Retourner la configuration lue
	return nil
}

// appliquerDetail règle le détail du journal par sous-système — section
// `debug.detail` (TO-DO 145).
//
// Un sous-système ou un niveau inconnu est une ERREUR, pas une ligne ignorée.
// On écrit cette section pour diagnostiquer : une faute de frappe laisserait le
// détail éteint, et l'on chercherait pendant une heure pourquoi la panne
// n'écrit rien.
//
// Les réglages sont posés tous ensemble ou pas du tout, et un sous-système
// absent de la section revient à son état d'origine : la configuration décrit
// l'état voulu, elle ne s'ajoute pas à ce qu'une commande aurait réglé avant.
func appliquerDetail(detail map[string]string) error {
	type reglage struct {
		sous   logs.SousSysteme
		niveau logs.Detail
		herite bool
	}

	noms := make([]string, 0, len(detail))
	for nom := range detail {
		noms = append(noms, nom)
	}
	sort.Strings(noms)

	voulus := make([]reglage, 0, len(noms))
	for _, nom := range noms {
		sous, connu := logs.SousSystemeNomme(nom)
		if !connu {
			return fmt.Errorf("debug.detail.%s : sous-système inconnu (admis : %s)",
				nom, logs.NomsDesSousSystemes())
		}
		niveau, herite, err := logs.LireDetail(detail[nom])
		if err != nil {
			return fmt.Errorf("debug.detail.%s : %w", nom, err)
		}
		voulus = append(voulus, reglage{sous, niveau, herite})
	}

	for _, s := range logs.SousSystemes() {
		logs.LaisserDetail(s)
	}
	for _, r := range voulus {
		if !r.herite {
			logs.ReglerDetail(r.sous, r.niveau)
		}
	}
	return nil
}
