package gpo

import "sort"

// Catalogue des modules GPO.
//
// Le catalogue définit les TYPES de modules et la FORME de leurs champs : c'est
// la partie structurelle, qui reste dans le code parce qu'elle correspond à ce
// que l'agent client sait faire. Ajouter un type ici sans écrire le handler
// correspondant côté agent donnerait un module sans effet.
//
// Le DOMAINE de valeurs des champs marqués Dynamic, lui, vit en base et est
// éditable par le groupe superadmin (voir restrictions.go). C'est ce qui permet
// d'accueillir un besoin custom — un service de monitoring maison, un paquet
// interne — sans toucher au code : soit en ajoutant la valeur à la liste, soit
// en passant le champ en mode motif.
//
// ORDRE D'APPLICATION
//
// ApplyOrder impose l'ordre d'exécution sur la machine, indépendamment de
// l'ordre de saisie. Réordonner les modules dans l'interface ne doit pas
// pouvoir changer le résultat.
//
// L'ordre suit les DÉPENDANCES RÉELLES entre modules, pas un classement
// thématique. Le fil conducteur : rien ne démarre avant que tout ce dont il
// dépend soit en place.
//
//	Phase 1 — 10-19   Fichiers et contenus
//	Phase 2 — 20-29   Sources et résolution (DNS, dépôts)
//	Phase 3 — 30-39   Paquets
//	Phase 4 — 40-59   Configuration système
//	Phase 5 — 60-69   Services
//	Phase 6 — 70-79   Ménage
//	Phase 7 — 80+     Environnement utilisateur
//
// POURQUOI LES FICHIERS EN PREMIER, et pas après les paquets comme dans la
// version initiale de ce catalogue. Trois raisons, chacune suffisante :
//
//   - un dépôt de paquets a besoin de sa clé de signature, qui est un fichier :
//     déployer les fichiers après les dépôts rendrait le dépôt inutilisable au
//     moment où on en a besoin ;
//   - un service doit démarrer avec sa configuration définitive. L'ancien ordre
//     (paquets 20, services 21, fichiers 30) le faisait démarrer sur la
//     configuration par défaut du paquet, puis déposait la vraie configuration
//     sans rien relancer : la machine tournait avec une conf que personne
//     n'avait choisie, jusqu'au prochain redémarrage ;
//   - file_deploy crée ses répertoires parents (MkdirAll côté agent), il n'a
//     donc pas besoin que le paquet ait créé /etc/<produit>/ au préalable.
//
// Exemple concret, un client VPN :
//
//	10-19  dépose /etc/openvpn/client.conf et la clé GPG du dépôt éditeur
//	20-29  déclare le dépôt de l'éditeur
//	30-39  installe le paquet openvpn
//	40-59  règle le pare-feu et les paramètres noyau nécessaires
//	60-69  démarre le service, qui lit une configuration déjà correcte
//
// CONSÉQUENCE SUR L'INSTALLATION DES PAQUETS. Déployer une configuration avant
// d'installer le paquet qui la possède crée un conflit de « conffile » :
// l'installeur trouve un fichier qu'il croit devoir écrire. L'agent force donc
// la conservation du fichier déjà présent (--force-confold côté dpkg), sans
// quoi le comportement dépendrait de la distribution et de son mode
// interactif — voir applyPackage dans l'agent.

// Types de modules du catalogue.
const (
	ModuleSSHServerConfig = "ssh_server_config"
	ModuleSysctl          = "sysctl"
	ModuleSudoersRule     = "sudoers_rule"
	ModulePackage         = "package"
	ModuleSystemdService  = "systemd_service"
	ModuleFileDeploy      = "file_deploy"
	ModuleUserEnv         = "user_env"
	ModuleUserCron        = "user_cron"

	// Phase 1 — fichiers et contenus
	ModuleDirectoryManage = "directory_manage"
	ModuleTemplatedFile   = "templated_file_deploy"
	ModuleTrustedCA       = "trusted_ca"

	// Phase 2 — sources et résolution
	ModuleDNSResolver = "dns_resolver"
	ModulePackageRepo = "package_repository"

	// Phase 4 — configuration système
	ModuleFirewallRule       = "firewall_rule"
	ModuleBootParams         = "boot_params"
	ModuleKernelModulePolicy = "kernel_module_policy"
	ModuleSSHKnownHosts      = "ssh_known_hosts"
	ModulePAMPolicy          = "pam_policy"
	ModuleLocalAccountPolicy = "local_account_policy"
	ModuleAuditdRule         = "auditd_rule"
	ModuleSELinuxMode        = "selinux_mode"
	ModuleNTPConfig          = "ntp_config"
	ModuleLogPolicy          = "log_policy"
	ModuleUpdatePolicy       = "update_policy"
	ModuleSystemEnv          = "system_env"
	ModuleResourceLimits     = "resource_limits"

	// Phase 1 — fichiers (suite)
	ModuleFileACL = "file_acl"

	// Phase 6 — ménage
	ModuleFileRetention = "file_retention"

	// Phase 7 — environnement utilisateur
	ModuleUserGroupMembership = "user_group_membership"
	ModuleUserShell           = "user_shell"
	ModuleUserPasswordPolicy  = "user_password_policy"
	ModuleUserSSHClientConfig = "user_ssh_client_config"
	ModuleUserGitConfig       = "user_git_config"
	ModuleUserResourceLimits  = "user_resource_limits"
)

// Bornes de phase, pour que les ApplyOrder ci-dessous se lisent comme un plan
// plutôt que comme une suite de nombres. Un module ajouté dans une phase prend
// un numéro libre de sa plage ; il n'y a jamais à renuméroter les autres.
const (
	phaseFiles    = 10 // fichiers et contenus
	phaseSources  = 20 // DNS, dépôts de paquets
	phasePackages = 30 // installation
	phaseConfig   = 40 // configuration système (jusqu'à 59)
	phaseServices = 60 // démarrage
	phaseCleanup  = 70 // ménage, après tout le reste
	phaseUser     = 80 // environnement utilisateur
)

// Catégories affichées dans l'interface web.
const (
	CategorySecurity = "Sécurité & réseau"
	CategorySystem   = "Système & services"
	CategoryFiles    = "Fichiers"
	CategoryUser     = "Environnement utilisateur"
)

// baseCatalog est le catalogue tel que défini dans le code, avant résolution des
// restrictions en base. Les champs Dynamic y ont Options vide : leurs valeurs
// sont injectées par resolveSchema.
var baseCatalog = []ModuleSchema{
	{
		Type:        ModuleSSHServerConfig,
		Label:       "Configuration SSH serveur",
		Category:    CategorySecurity,
		Description: "Règle sshd via un fragment dédié /etc/ssh/sshd_config.d/99-vaultaire-gpo.conf. Le fichier principal n'est jamais modifié et la configuration est validée (sshd -t) avant rechargement.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 4, // ssh_server_config
		Fields: []FieldSchema{
			{Name: "permit_root_login", Label: "PermitRootLogin", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "no", "prohibit-password", "forced-commands-only"},
				Default: "unchanged", Required: true},
			{Name: "password_authentication", Label: "PasswordAuthentication", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "no"}, Default: "unchanged", Required: true},
			{Name: "pubkey_authentication", Label: "PubkeyAuthentication", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "no"}, Default: "unchanged", Required: true},
			{Name: "max_auth_tries", Label: "MaxAuthTries", Type: FieldInt, Min: 1, Max: 10,
				Help: "Laisser vide pour ne pas imposer de valeur."},
			{Name: "client_alive_interval", Label: "ClientAliveInterval (s)", Type: FieldInt, Min: 0, Max: 86400,
				Help: "Laisser vide pour ne pas imposer de valeur."},
			{Name: "allow_tcp_forwarding", Label: "AllowTcpForwarding", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "no", "local", "remote"}, Default: "unchanged"},
			{Name: "x11_forwarding", Label: "X11Forwarding", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "no"}, Default: "unchanged"},
			{Name: "banner_text", Label: "Bannière de connexion", Type: FieldText, MaxLen: 4096,
				Help: "Déposée dans un fichier dédié et référencée par la directive Banner."},
		},
	},
	{
		Type:        ModuleSysctl,
		Label:       "Paramètre noyau (sysctl)",
		Category:    CategorySecurity,
		Description: "Fixe une clé sysctl. Écrit dans /etc/sysctl.d/, jamais dans /etc/sysctl.conf. Les clés disponibles sont éditables dans Admin → GPO → Restrictions.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig,     // sysctl
		Fields: []FieldSchema{
			{Name: "key", Label: "Clé", Type: FieldEnum, Required: true, Dynamic: true, MaxLen: 128},
			{Name: "value", Label: "Valeur", Type: FieldString, Required: true, Dynamic: true, MaxLen: 128,
				Help: "Forme acceptée définie par la règle sysctl/value dans les Restrictions."},
		},
	},
	{
		Type:        ModuleSudoersRule,
		Label:       "Droits sudo (par groupe)",
		Category:    CategorySecurity,
		Description: "Génère un fichier /etc/sudoers.d/ depuis un template contrôlé côté agent. Aucune ligne sudoers brute n'est transmise : seuls un groupe et un identifiant de jeu de commandes circulent.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 16, // sudoers_rule
		Fields: []FieldSchema{
			{Name: "group", Label: "Groupe POSIX bénéficiaire", Type: FieldIdent, Required: true, MaxLen: 32},
			{Name: "command_set", Label: "Jeu de commandes", Type: FieldEnum, Required: true,
				Dynamic: true, Default: "service_control", MaxLen: 64},
			{Name: "nopasswd", Label: "Sans mot de passe (NOPASSWD)", Type: FieldBool, Default: "false",
				Help: "À éviter : supprime la ré-authentification avant élévation."},
		},
	},
	{
		Type:        ModulePackage,
		Label:       "Paquet logiciel",
		Category:    CategorySystem,
		Description: "Garantit la présence ou l'absence d'un paquet. Appliqué avant les modules de service, pour qu'une unité dépendante d'un paquet existe au moment de son activation. Les paquets disponibles sont éditables dans les Restrictions.",
		Scope:       ScopeMachine,
		ApplyOrder:  phasePackages,   // package
		Fields: []FieldSchema{
			{Name: "package", Label: "Paquet", Type: FieldEnum, Required: true, Dynamic: true, MaxLen: 128},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
			{Name: "version", Label: "Version épinglée", Type: FieldString, MaxLen: 64,
				Help: "Laisser vide pour la dernière version disponible dans les dépôts configurés."},
		},
	},
	{
		Type:        ModuleSystemdService,
		Label:       "Service systemd",
		Category:    CategorySystem,
		Description: "Force l'état d'une unité systemd (activation au boot, état courant, masquage). Les unités disponibles sont éditables dans les Restrictions — c'est là qu'on déclare un service maison.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseServices,   // systemd_service
		Fields: []FieldSchema{
			{Name: "service", Label: "Unité", Type: FieldEnum, Required: true, Dynamic: true, MaxLen: 128},
			{Name: "enabled", Label: "Activation au démarrage", Type: FieldEnum, Required: true,
				Options: []string{"unchanged", "enabled", "disabled"}, Default: "unchanged"},
			{Name: "state", Label: "État courant", Type: FieldEnum, Required: true,
				Options: []string{"unchanged", "started", "stopped", "restarted"}, Default: "unchanged"},
			{Name: "masked", Label: "Masquer l'unité", Type: FieldBool, Default: "false",
				Help: "Le masquage rend l'unité indémarrable, y compris par dépendance."},
		},
	},
	{
		Type:        ModuleFileDeploy,
		Label:       "Déploiement de fichier",
		Category:    CategoryFiles,
		Description: "Dépose un fichier avec contenu, permissions et propriétaire. Les emplacements autorisés et refusés sont éditables dans les Restrictions ; en scope user, le chemin s'exprime sous " + userHomePlaceholder + "/.",
		Scope:       ScopeBoth,
		ApplyOrder:  phaseFiles + 1,  // file_deploy
		Fields: []FieldSchema{
			{Name: "path", Label: "Chemin", Type: FieldPath, Required: true, MaxLen: 512,
				Help: "Scope machine : chemin absolu hors zones refusées. Scope user : " + userHomePlaceholder + "/chemin/relatif."},
			{Name: "content", Label: "Contenu", Type: FieldText, MaxLen: 262144},
			{Name: "mode", Label: "Permissions", Type: FieldMode, Required: true, Default: "0644",
				Help: "Notation octale à 3 chiffres. Les bits setuid/setgid ne sont pas exprimables."},
			{Name: "owner", Label: "Propriétaire", Type: FieldIdent, MaxLen: 32,
				Help: "Laisser vide pour root en scope machine, pour l'utilisateur cible en scope user."},
			{Name: "group", Label: "Groupe", Type: FieldIdent, MaxLen: 32},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleDirectoryManage,
		Label:       "Répertoire",
		Category:    CategoryFiles,
		Description: "Crée un répertoire avec ses permissions et son propriétaire. Appliqué avant les fichiers, pour qu'un dépôt puisse viser une arborescence maîtrisée plutôt que celle créée implicitement par le premier fichier.",
		Scope:       ScopeBoth,
		ApplyOrder:  phaseFiles, // avant file_deploy
		Fields: []FieldSchema{
			{Name: "path", Label: "Chemin", Type: FieldPath, Required: true, MaxLen: 512,
				Help: "Scope machine : chemin absolu hors zones refusées. Scope user : " + userHomePlaceholder + "/chemin/relatif."},
			{Name: "mode", Label: "Permissions", Type: FieldMode, Required: true, Default: "0755"},
			{Name: "owner", Label: "Propriétaire", Type: FieldIdent, MaxLen: 32},
			{Name: "group", Label: "Groupe", Type: FieldIdent, MaxLen: 32},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present",
				Help: "« absent » ne supprime qu'un répertoire vide : effacer récursivement depuis une GPO transformerait une faute de frappe en perte de données."},
		},
	},
	{
		Type:        ModuleTemplatedFile,
		Label:       "Fichier avec substitution",
		Category:    CategoryFiles,
		Description: "Comme le déploiement de fichier, mais le contenu accepte des marqueurs remplacés par l'agent : {{hostname}}, {{fqdn}}, {{username}}, {{domain}}. Évite de dupliquer un module par machine.",
		Scope:       ScopeBoth,
		ApplyOrder:  phaseFiles + 2, // après file_deploy
		Fields: []FieldSchema{
			{Name: "path", Label: "Chemin", Type: FieldPath, Required: true, MaxLen: 512},
			{Name: "content", Label: "Contenu", Type: FieldText, MaxLen: 262144,
				Help: "Marqueurs disponibles : {{hostname}}, {{fqdn}}, {{username}}, {{domain}}. Un marqueur inconnu est laissé tel quel plutôt que remplacé par du vide — une substitution silencieuse produirait un fichier syntaxiquement correct mais faux."},
			{Name: "mode", Label: "Permissions", Type: FieldMode, Required: true, Default: "0644"},
			{Name: "owner", Label: "Propriétaire", Type: FieldIdent, MaxLen: 32},
			{Name: "group", Label: "Groupe", Type: FieldIdent, MaxLen: 32},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleTrustedCA,
		Label:       "Autorité de certification",
		Category:    CategorySecurity,
		Description: "Installe ou retire une CA interne dans le magasin de confiance du système. Appliqué avant les dépôts de paquets : un dépôt en HTTPS signé par une CA interne est injoignable tant qu'elle n'est pas reconnue.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseFiles + 4, // dernier de la phase fichiers, avant les dépôts
		Fields: []FieldSchema{
			{Name: "name", Label: "Nom", Type: FieldIdent, Required: true, MaxLen: 64,
				Help: "Sert de nom de fichier dans le magasin. Un nom déjà présent est remplacé."},
			{Name: "certificate", Label: "Certificat (PEM)", Type: FieldText, Required: true, MaxLen: 32768,
				Help: "Bloc BEGIN CERTIFICATE. La clé privée n'a rien à faire ici et est refusée."},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleDNSResolver,
		Label:       "Résolution DNS",
		Category:    CategorySecurity,
		Description: "Fixe les serveurs DNS et le domaine de recherche. Appliqué avant les dépôts : sans résolution, aucun dépôt n'est joignable. Écrit dans un fichier dédié, jamais directement dans /etc/resolv.conf, que la plupart des distributions régénèrent.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseSources, // premier de la phase sources
		Fields: []FieldSchema{
			{Name: "servers", Label: "Serveurs DNS", Type: FieldString, Required: true, MaxLen: 256,
				Help: "Adresses IP séparées par des virgules, dans l'ordre d'interrogation."},
			{Name: "search_domain", Label: "Domaine de recherche", Type: FieldString, MaxLen: 256,
				Help: "Domaines séparés par des virgules. Laisser vide pour ne pas en imposer."},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModulePackageRepo,
		Label:       "Dépôt de paquets",
		Category:    CategorySystem,
		Description: "Déclare un dépôt de paquets autorisé. C'est ce qui permet au module Paquet d'installer depuis une source maîtrisée plutôt que depuis ce que la machine avait déjà. Les URL autorisées sont éditables dans les Restrictions.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseSources + 1, // après le DNS, avant les paquets
		Fields: []FieldSchema{
			{Name: "name", Label: "Nom", Type: FieldIdent, Required: true, MaxLen: 64,
				Help: "Sert de nom de fichier dans /etc/apt/sources.list.d/ ou /etc/yum.repos.d/."},
			{Name: "url", Label: "URL", Type: FieldString, Required: true, Dynamic: true, MaxLen: 512,
				Help: "Domaine autorisé défini par la règle package_repository/url dans les Restrictions."},
			{Name: "suite", Label: "Suite / composants", Type: FieldString, MaxLen: 256,
				Help: "Debian/Ubuntu : « stable main ». Ignoré sur les distributions RPM."},
			{Name: "gpg_key_path", Label: "Chemin de la clé de signature", Type: FieldPath, MaxLen: 512,
				Help: "Chemin d'un fichier déposé par un module de la phase fichiers. Laisser vide désactive la vérification de signature — à n'utiliser que sur un dépôt local de confiance."},
			{Name: "enabled", Label: "Actif", Type: FieldBool, Default: "true"},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleFirewallRule,
		Label:       "Règle de pare-feu",
		Category:    CategorySecurity,
		Description: "Ouvre ou ferme un port. Les règles sont posées dans une zone ou une table dédiée à Vaultaire, jamais mélangées aux règles saisies à la main : une GPO retirée ne doit pas emporter avec elle une règle posée par un administrateur.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 10, // avant les services, qui écouteront sur ces ports
		Fields: []FieldSchema{
			{Name: "port", Label: "Port", Type: FieldInt, Required: true, Min: 1, Max: 65535},
			{Name: "protocol", Label: "Protocole", Type: FieldEnum, Required: true,
				Options: []string{"tcp", "udp"}, Default: "tcp"},
			{Name: "source", Label: "Source autorisée", Type: FieldString, MaxLen: 128,
				Help: "Adresse ou réseau CIDR. Laisser vide pour toute origine."},
			{Name: "action", Label: "Action", Type: FieldEnum, Required: true,
				Options: []string{"allow", "deny"}, Default: "allow"},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleFileACL,
		Label:       "ACL POSIX",
		Category:    CategoryFiles,
		Description: "Pose une ACL POSIX sur un fichier ou un répertoire, au-delà du couple propriétaire/groupe. Appliqué après les modules de dépôt, pour que la cible existe.",
		Scope:       ScopeBoth,
		ApplyOrder:  phaseFiles + 3,
		Fields: []FieldSchema{
			{Name: "path", Label: "Chemin", Type: FieldPath, Required: true, MaxLen: 512},
			{Name: "kind", Label: "Bénéficiaire", Type: FieldEnum, Required: true,
				Options: []string{"user", "group"}, Default: "group"},
			{Name: "target", Label: "Utilisateur ou groupe", Type: FieldIdent, Required: true, MaxLen: 32},
			{Name: "permissions", Label: "Droits", Type: FieldEnum, Required: true,
				Options: []string{"r", "rw", "rx", "rwx", "---"}, Default: "r",
				Help: "« --- » retire tout droit sans supprimer l'entrée : utile pour exclure explicitement."},
			{Name: "recursive", Label: "Récursif", Type: FieldBool, Default: "false",
				Help: "Sur un répertoire uniquement. Applique aussi l'ACL par défaut, héritée par les fichiers créés ensuite."},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleBootParams,
		Label:       "Paramètres noyau au démarrage (GRUB)",
		Category:    CategorySystem,
		Description: "Ajoute des paramètres à la ligne de commande du noyau. Distinct de sysctl, qui agit à chaud : ceux-ci ne prennent effet qu'au prochain redémarrage. La configuration GRUB est régénérée puis validée ; en cas d'échec, l'état précédent est restauré.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 1,
		Fields: []FieldSchema{
			{Name: "parameter", Label: "Paramètre", Type: FieldString, Required: true, MaxLen: 128,
				Help: "Forme « clé=valeur » ou drapeau seul (ex. audit=1, quiet). Un seul paramètre par module."},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleKernelModulePolicy,
		Label:       "Module noyau interdit",
		Category:    CategorySecurity,
		Description: "Empêche le chargement d'un module noyau — par exemple usb-storage pour bloquer les clés USB. Écrit dans /etc/modprobe.d/ et retire le module s'il est déjà chargé. La liste des modules gérables est éditable dans les Restrictions.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 2,
		Fields: []FieldSchema{
			{Name: "module", Label: "Module noyau", Type: FieldEnum, Required: true, Dynamic: true, MaxLen: 64},
			{Name: "unload_now", Label: "Décharger immédiatement", Type: FieldBool, Default: "false",
				Help: "Sans cette option, l'interdiction ne vaut que pour les chargements futurs : un module déjà en mémoire le reste jusqu'au redémarrage."},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleSSHKnownHosts,
		Label:       "Serveurs SSH connus",
		Category:    CategorySecurity,
		Description: "Pré-remplit /etc/ssh/ssh_known_hosts, la liste de confiance commune à tous les utilisateurs de la machine, et règle StrictHostKeyChecking. Évite que chacun accepte une empreinte au petit bonheur à la première connexion.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 5,
		Fields: []FieldSchema{
			{Name: "host", Label: "Hôte", Type: FieldString, Required: true, MaxLen: 256,
				Help: "Nom d'hôte ou adresse. Plusieurs formes séparées par des virgules (ex. srv1,srv1.example.fr,10.0.0.1)."},
			{Name: "key", Label: "Clé publique du serveur", Type: FieldText, Required: true, MaxLen: 4096,
				Help: "Ligne complète telle que produite par ssh-keyscan, type de clé compris."},
			{Name: "strict_host_key_checking", Label: "StrictHostKeyChecking", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "accept-new", "no"}, Default: "unchanged",
				Help: "« yes » refuse tout serveur absent de cette liste. À n'activer qu'une fois la liste complète."},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModulePAMPolicy,
		Label:       "Politique de mot de passe et de verrouillage",
		Category:    CategorySecurity,
		Description: "Règle la complexité des mots de passe (pam_pwquality) et le verrouillage après échecs (pam_faillock). N'écrit QUE dans des fichiers .d/ dédiés — les piles /etc/pam.d/ ne sont jamais touchées, car une pile PAM fautive rend la machine inaccessible, y compris en console.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 6,
		Fields: []FieldSchema{
			{Name: "min_length", Label: "Longueur minimale", Type: FieldInt, Min: 0, Max: 64,
				Help: "0 ou vide : ne pas imposer."},
			{Name: "min_classes", Label: "Classes de caractères minimales", Type: FieldInt, Min: 0, Max: 4,
				Help: "Minuscules, majuscules, chiffres, symboles."},
			{Name: "remember", Label: "Historique interdit", Type: FieldInt, Min: 0, Max: 50,
				Help: "Nombre d'anciens mots de passe refusés à la réutilisation."},
			{Name: "deny_after", Label: "Verrouillage après N échecs", Type: FieldInt, Min: 0, Max: 100,
				Help: "0 ou vide : pas de verrouillage."},
			{Name: "unlock_time", Label: "Déverrouillage automatique (s)", Type: FieldInt, Min: 0, Max: 86400,
				Help: "0 signifie verrouillage permanent jusqu'à intervention. Une valeur non nulle est fortement conseillée : sans elle, une attaque par échecs répétés verrouille durablement des comptes légitimes."},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleLocalAccountPolicy,
		Label:       "Politique des comptes locaux",
		Category:    CategorySecurity,
		Description: "Applique une expiration ou désactive l'authentification par mot de passe des comptes locaux non gérés par Vaultaire. root et les comptes système (uid < 1000) sont exclus par construction : les inclure couperait le dernier accès de secours à la machine.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 7,
		Fields: []FieldSchema{
			{Name: "action", Label: "Action", Type: FieldEnum, Required: true,
				Options: []string{"report_only", "lock_password", "expire"}, Default: "report_only",
				Help: "« report_only » se contente de lister les comptes concernés dans le rapport, sans rien modifier. À utiliser d'abord pour vérifier la portée."},
			{Name: "max_age_days", Label: "Âge maximal du mot de passe (jours)", Type: FieldInt, Min: 0, Max: 3650,
				Help: "0 ou vide : ne pas imposer."},
			{Name: "inactive_days", Label: "Désactivation après inactivité (jours)", Type: FieldInt, Min: 0, Max: 3650},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleAuditdRule,
		Label:       "Règle d'audit",
		Category:    CategorySecurity,
		Description: "Trace les accès à un chemin au niveau noyau, via /etc/audit/rules.d/. Répond à « qui a modifié ce fichier, et quand ». La règle est décrite par champs, jamais fournie en syntaxe auditctl brute.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 8,
		Fields: []FieldSchema{
			{Name: "path", Label: "Chemin surveillé", Type: FieldPath, Required: true, MaxLen: 512},
			{Name: "permissions", Label: "Accès tracés", Type: FieldEnum, Required: true,
				Options: []string{"wa", "rwa", "rwxa", "x"}, Default: "wa",
				Help: "w écriture, a changement d'attribut, r lecture, x exécution. « wa » couvre la modification sans noyer le journal sous les lectures."},
			{Name: "key", Label: "Étiquette", Type: FieldIdent, Required: true, MaxLen: 32,
				Help: "Sert à retrouver les événements : ausearch -k <étiquette>."},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleSELinuxMode,
		Label:       "Mode SELinux",
		Category:    CategorySecurity,
		Description: "Fixe le mode SELinux. Le passage en enforcing est refusé si le système n'a jamais été réétiqueté : sur un système resté permissive, des étiquettes manquantes empêcheraient des services de démarrer — parfois sshd, donc sans accès pour corriger.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 9,
		Fields: []FieldSchema{
			{Name: "mode", Label: "Mode", Type: FieldEnum, Required: true,
				Options: []string{"unchanged", "permissive", "enforcing"}, Default: "unchanged"},
			{Name: "boolean_name", Label: "Booléen SELinux", Type: FieldIdent, MaxLen: 64,
				Help: "Facultatif. Nom d'un booléen à régler en plus du mode (ex. httpd_can_network_connect)."},
			{Name: "boolean_value", Label: "Valeur du booléen", Type: FieldEnum,
				Options: []string{"unchanged", "on", "off"}, Default: "unchanged"},
		},
	},
	{
		Type:        ModuleNTPConfig,
		Label:       "Synchronisation horaire (NTP)",
		Category:    CategorySystem,
		Description: "Fixe les serveurs de temps. Une horloge décalée casse la validation des certificats et l'authentification Kerberos, et rend les journaux incomparables entre machines.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 11,
		Fields: []FieldSchema{
			{Name: "servers", Label: "Serveurs NTP", Type: FieldString, Required: true, MaxLen: 512,
				Help: "Noms ou adresses séparés par des virgules."},
			{Name: "fallback_servers", Label: "Serveurs de secours", Type: FieldString, MaxLen: 512},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleLogPolicy,
		Label:       "Rétention des journaux",
		Category:    CategorySystem,
		Description: "Règle la rotation et la rétention : taille maximale du journal systemd et durée de conservation. Un disque saturé par les journaux met une machine hors service aussi sûrement qu'une panne.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 12,
		Fields: []FieldSchema{
			{Name: "max_use", Label: "Taille maximale du journal", Type: FieldString, MaxLen: 16,
				Help: "Forme systemd : 500M, 2G. Laisser vide pour ne pas imposer."},
			{Name: "max_retention_days", Label: "Conservation (jours)", Type: FieldInt, Min: 0, Max: 3650},
			{Name: "forward_to_syslog", Label: "Transférer vers syslog", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "no"}, Default: "unchanged"},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleUpdatePolicy,
		Label:       "Mises à jour automatiques",
		Category:    CategorySystem,
		Description: "Active ou désactive les mises à jour automatiques. Le redémarrage automatique est un champ distinct et vaut « non » par défaut : une machine qui redémarre seule en pleine journée est un incident, pas une mise à jour.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 13,
		Fields: []FieldSchema{
			{Name: "enabled", Label: "Mises à jour automatiques", Type: FieldEnum, Required: true,
				Options: []string{"unchanged", "enabled", "disabled"}, Default: "unchanged"},
			{Name: "security_only", Label: "Sécurité uniquement", Type: FieldBool, Default: "true"},
			{Name: "reboot_if_needed", Label: "Redémarrer si nécessaire", Type: FieldBool, Default: "false"},
			{Name: "reboot_time", Label: "Heure de redémarrage", Type: FieldString, MaxLen: 8,
				Help: "Forme HH:MM. Ignoré si le redémarrage automatique est désactivé."},
		},
	},
	{
		Type:        ModuleSystemEnv,
		Label:       "Variable d'environnement système",
		Category:    CategorySystem,
		Description: "Définit une variable dans /etc/environment, visible par tous les utilisateurs et tous les services. Distinct de la variable utilisateur, qui ne vaut que pour une session. La liste des variables interdites des Restrictions s'applique ici aussi.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 14,
		Fields: []FieldSchema{
			{Name: "name", Label: "Nom", Type: FieldEnvName, Required: true, MaxLen: 64},
			{Name: "value", Label: "Valeur", Type: FieldString, Required: true, MaxLen: 1024},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleResourceLimits,
		Label:       "Limites de ressources (machine)",
		Category:    CategorySystem,
		Description: "Fixe une limite système via /etc/security/limits.d/. S'applique à tous les utilisateurs ou à un groupe. Distinct des quotas par utilisateur, qui passent par les slices systemd.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseConfig + 15,
		Fields: []FieldSchema{
			{Name: "domain", Label: "Portée", Type: FieldString, Required: true, MaxLen: 64, Default: "*",
				Help: "« * » pour tous, « @groupe » pour un groupe, ou un nom d'utilisateur."},
			{Name: "limit_type", Label: "Type", Type: FieldEnum, Required: true,
				Options: []string{"soft", "hard"}, Default: "hard"},
			{Name: "item", Label: "Ressource", Type: FieldEnum, Required: true,
				Options: []string{"nofile", "nproc", "memlock", "core", "fsize", "stack"}, Default: "nofile"},
			{Name: "value", Label: "Valeur", Type: FieldString, Required: true, MaxLen: 16,
				Help: "Entier, ou « unlimited »."},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleFileRetention,
		Label:       "Purge de fichiers",
		Category:    CategoryFiles,
		Description: "Supprime les fichiers d'un répertoire au-delà d'un âge. Appliqué en dernier, après tout ce qui dépose des fichiers. Le motif ne peut pas contenir de séparateur de chemin, l'âge minimal est d'un jour, les liens symboliques ne sont jamais suivis, et les emplacements refusés des Restrictions s'appliquent.",
		Scope:       ScopeMachine,
		ApplyOrder:  phaseCleanup,
		Fields: []FieldSchema{
			{Name: "directory", Label: "Répertoire", Type: FieldPath, Required: true, MaxLen: 512},
			{Name: "pattern", Label: "Motif", Type: FieldString, Required: true, MaxLen: 128, Default: "*.log",
				Help: "Motif de nom de fichier, sans « / ». Un motif traversant l'arborescence est refusé."},
			{Name: "older_than_days", Label: "Plus vieux que (jours)", Type: FieldInt, Required: true, Min: 1, Max: 3650,
				Default: "30", Help: "Minimum 1 : une purge à 0 jour effacerait un fichier au moment même où il est écrit."},
			{Name: "recursive", Label: "Récursif", Type: FieldBool, Default: "false"},
		},
	},
	{
		Type:        ModuleUserGroupMembership,
		Label:       "Appartenance à un groupe local",
		Category:    CategoryUser,
		Description: "Ajoute ou retire l'utilisateur d'un groupe POSIX local. Appliqué en premier de la phase utilisateur, parce qu'un droit accordé par un groupe conditionne ce que les modules suivants peuvent faire. La liste des groupes attribuables est éditable dans les Restrictions — c'est un point de vigilance : certains groupes (docker, lxd, disk) équivalent à un accès root sur la machine.",
		Scope:       ScopeUser,
		ApplyOrder:  phaseUser,
		Fields: []FieldSchema{
			{Name: "group", Label: "Groupe local", Type: FieldEnum, Required: true, Dynamic: true, MaxLen: 32},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleUserShell,
		Label:       "Shell de connexion",
		Category:    CategoryUser,
		Description: "Force le shell de connexion de l'utilisateur. Les shells attribuables sont éditables dans les Restrictions, ce qui permet de proposer un shell restreint (rbash) ou d'interdire la connexion interactive (nologin) sans toucher au code.",
		Scope:       ScopeUser,
		ApplyOrder:  phaseUser + 1,
		Fields: []FieldSchema{
			{Name: "shell", Label: "Shell", Type: FieldEnum, Required: true, Dynamic: true, MaxLen: 64},
		},
	},
	{
		Type:        ModuleUserPasswordPolicy,
		Label:       "Expiration du mot de passe (utilisateur)",
		Category:    CategoryUser,
		Description: "Force le changement au prochain login, ou fixe une expiration propre à cet utilisateur. Distinct de la politique machine, qui règle la complexité pour tout le monde.",
		Scope:       ScopeUser,
		ApplyOrder:  phaseUser + 2,
		Fields: []FieldSchema{
			{Name: "force_change", Label: "Changement au prochain login", Type: FieldBool, Default: "false",
				Help: "Attention : combiné à un shell nologin, l'utilisateur ne peut plus changer son mot de passe et se retrouve bloqué."},
			{Name: "max_age_days", Label: "Validité (jours)", Type: FieldInt, Min: 0, Max: 3650,
				Help: "0 ou vide : ne pas imposer."},
			{Name: "warn_days", Label: "Avertissement avant expiration (jours)", Type: FieldInt, Min: 0, Max: 365},
		},
	},
	{
		Type:        ModuleUserSSHClientConfig,
		Label:       "Configuration cliente SSH",
		Category:    CategoryUser,
		Description: "Écrit une entrée Host dans ~/.ssh/config, dans un bloc balisé. Le reste du fichier, écrit par l'utilisateur, n'est jamais touché.",
		Scope:       ScopeUser,
		ApplyOrder:  phaseUser + 4,
		Fields: []FieldSchema{
			{Name: "host_alias", Label: "Alias", Type: FieldString, Required: true, MaxLen: 64,
				Help: "Le nom tapé après « ssh »."},
			{Name: "hostname", Label: "Hôte réel", Type: FieldString, Required: true, MaxLen: 256},
			{Name: "user", Label: "Utilisateur distant", Type: FieldIdent, MaxLen: 32},
			{Name: "port", Label: "Port", Type: FieldInt, Min: 1, Max: 65535},
			{Name: "proxy_jump", Label: "Rebond (ProxyJump)", Type: FieldString, MaxLen: 256},
			{Name: "identity_file", Label: "Clé à utiliser", Type: FieldString, MaxLen: 256,
				Help: "Chemin relatif au home, ex. .ssh/id_ed25519_prod."},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleUserGitConfig,
		Label:       "Configuration git",
		Category:    CategoryUser,
		Description: "Règle une clé du ~/.gitconfig de l'utilisateur. Les clés sont choisies dans une liste fermée plutôt que libres : git permet de définir des commandes exécutées automatiquement (core.pager, filtres, hooks), qui donneraient une exécution de code arbitraire dans le contexte de l'utilisateur.",
		Scope:       ScopeUser,
		ApplyOrder:  phaseUser + 5,
		Fields: []FieldSchema{
			{Name: "key", Label: "Clé", Type: FieldEnum, Required: true,
				Options: []string{
					"user.name", "user.email", "user.signingkey",
					"init.defaultBranch", "pull.rebase", "push.default",
					"commit.gpgsign", "tag.gpgsign",
					"core.autocrlf", "core.fileMode",
					"http.sslVerify", "credential.helper",
				},
				Default: "user.email",
				Help:    "Liste fermée. Les clés permettant d'exécuter une commande (core.pager, alias, filtres) sont volontairement absentes."},
			{Name: "value", Label: "Valeur", Type: FieldString, Required: true, MaxLen: 256},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleUserResourceLimits,
		Label:       "Quota de ressources (utilisateur)",
		Category:    CategoryUser,
		Description: "Limite la consommation CPU et mémoire de l'utilisateur via sa slice systemd. Empêche une session de saturer une machine partagée. Distinct des limites machine, qui passent par limits.d.",
		Scope:       ScopeUser,
		ApplyOrder:  phaseUser + 6,
		Fields: []FieldSchema{
			{Name: "cpu_quota", Label: "Quota CPU", Type: FieldString, MaxLen: 8,
				Help: "En pourcentage, ex. 200% pour deux cœurs. Laisser vide pour ne pas limiter."},
			{Name: "memory_max", Label: "Mémoire maximale", Type: FieldString, MaxLen: 16,
				Help: "Forme systemd : 512M, 4G. Au-delà, les processus de l'utilisateur sont tués par le noyau."},
			{Name: "tasks_max", Label: "Processus maximum", Type: FieldInt, Min: 0, Max: 100000},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleUserEnv,
		Label:       "Variable d'environnement utilisateur",
		Category:    CategoryUser,
		Description: "Définit une variable dans un fichier dédié sourcé depuis le shell de l'utilisateur (bloc balisé, le .bashrc n'est jamais réécrit). La liste des variables interdites est éditable dans les Restrictions.",
		Scope:       ScopeUser,
		ApplyOrder:  phaseUser + 3,   // user_env
		Fields: []FieldSchema{
			{Name: "name", Label: "Nom", Type: FieldEnvName, Required: true, MaxLen: 64},
			{Name: "value", Label: "Valeur", Type: FieldString, Required: true, MaxLen: 1024},
		},
	},
	{
		Type:        ModuleUserCron,
		Label:       "Tâche planifiée utilisateur",
		Category:    CategoryUser,
		Description: "Crée un timer systemd --user. La tâche référence un identifiant de commande implémenté côté agent ; la liste des identifiants est éditable dans les Restrictions.",
		Scope:       ScopeUser,
		ApplyOrder:  phaseUser + 7,   // user_cron
		Fields: []FieldSchema{
			{Name: "schedule", Label: "Planification (cron 5 champs)", Type: FieldCron, Required: true,
				Default: "0 9 * * *", MaxLen: 128},
			{Name: "command_id", Label: "Commande", Type: FieldEnum, Required: true, Dynamic: true, MaxLen: 64},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
}

// baseIndex permet une résolution par type en O(1).
var baseIndex = func() map[string]ModuleSchema {
	m := make(map[string]ModuleSchema, len(baseCatalog))
	for _, s := range baseCatalog {
		m[s.Type] = s
	}
	return m
}()

// resolveSchema renseigne les champs Dynamic depuis les restrictions en vigueur.
//
// Le schéma est copié en profondeur (le slice Fields et chaque slice Options),
// pour qu'une résolution ne modifie jamais le catalogue de base. Sans cette
// copie, deux appels concurrents se marcheraient dessus.
func resolveSchema(s ModuleSchema) ModuleSchema {
	rs := Restrictions()
	resolved := s
	resolved.Fields = make([]FieldSchema, len(s.Fields))

	for i, f := range s.Fields {
		field := f
		if f.Options != nil {
			field.Options = append([]string(nil), f.Options...)
		}
		if f.Dynamic {
			rule := rs.Rule(s.Type, f.Name)
			field.Mode = rule.Mode
			field.AllowPattern = rule.AllowPattern
			field.DenyPattern = rule.DenyPattern
			field.Options = rs.Values(s.Type, f.Name)

			// Hors mode liste, la valeur est saisie librement : le type d'entrée
			// devient une chaîne pour que l'interface web affiche un champ texte
			// plutôt qu'un menu déroulant vide.
			if rule.Mode != FieldModeList {
				field.Type = FieldString
			}
		}
		resolved.Fields[i] = field
	}
	return resolved
}

// BaseSchemaFor retourne le schéma brut d'un module, sans consulter les
// restrictions. Utilisé par les vérifications structurelles (scope), qui n'ont
// pas besoin du domaine de valeurs et ne doivent pas dépendre de la base.
func BaseSchemaFor(moduleType string) (ModuleSchema, bool) {
	s, ok := baseIndex[moduleType]
	return s, ok
}

// SchemaFor retourne le schéma résolu d'un module : forme issue du code, domaine
// de valeurs issu de la base.
func SchemaFor(moduleType string) (ModuleSchema, bool) {
	s, ok := baseIndex[moduleType]
	if !ok {
		return ModuleSchema{}, false
	}
	return resolveSchema(s), true
}

// Catalog retourne le catalogue résolu, trié par ordre d'application puis libellé.
func Catalog() []ModuleSchema {
	out := make([]ModuleSchema, 0, len(baseCatalog))
	for _, s := range baseCatalog {
		out = append(out, resolveSchema(s))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ApplyOrder != out[j].ApplyOrder {
			return out[i].ApplyOrder < out[j].ApplyOrder
		}
		return out[i].Label < out[j].Label
	})
	return out
}

// CatalogForScope retourne les modules utilisables dans une GPO de ce scope.
func CatalogForScope(policyScope Scope) []ModuleSchema {
	var out []ModuleSchema
	for _, s := range Catalog() {
		if s.AllowedInScope(policyScope) {
			out = append(out, s)
		}
	}
	return out
}

// ModuleTypes retourne tous les types du catalogue.
func ModuleTypes() []string {
	out := make([]string, 0, len(baseCatalog))
	for _, s := range baseCatalog {
		out = append(out, s.Type)
	}
	sort.Strings(out)
	return out
}

// ModuleLabel retourne le libellé lisible d'un type de module.
func ModuleLabel(moduleType string) string {
	if s, ok := baseIndex[moduleType]; ok {
		return s.Label
	}
	return moduleType
}

// DefaultParams construit la map de paramètres par défaut d'un module, utilisée
// pour préremplir les formulaires web.
func DefaultParams(moduleType string) map[string]string {
	schema, ok := SchemaFor(moduleType)
	if !ok {
		return nil
	}
	params := make(map[string]string, len(schema.Fields))
	for _, f := range schema.Fields {
		params[f.Name] = f.Default
	}
	return params
}

// CategoriesForScope retourne les catégories présentes pour un scope, dans
// l'ordre d'application, pour grouper l'affichage web.
func CategoriesForScope(policyScope Scope) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range CatalogForScope(policyScope) {
		if !seen[s.Category] {
			seen[s.Category] = true
			out = append(out, s.Category)
		}
	}
	return out
}
